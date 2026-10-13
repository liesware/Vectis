"""One existing subject seed protects both tokenization and FPE."""
import copy

from lib.assertions import require
from lib.casekit import CaseSet
from lib.client import StatusClient
from lib.fixtures import create_api_key_pair, create_key
from lib.results import CaseResult

cases = CaseSet()


@cases("positive.fpe.subjects")
def run_subject_fpe(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        kid = create_key(ctx.client, {"tag":"shared-subject-fpe","profile":"hybrid-performance-v1"})
        creator={"name":"seed-origin-v1","kid":kid,"token_prefix":"shared_seed","token_len":32,"max_plaintext_len":128,"one_time":False,"subject_mode":"stored"}
        ctx.config_data["tokenization_profiles"].append(creator)
        profiles=[]
        for authenticated in [False,True]:
            profile={"name":f"shared-fpe-{authenticated}","kid":kid,"fpe_version":"fpe-ff1-2025","alphabet_preset":"num","preserve_characters":"-","min_len":6,"max_len":32,"tweak_aad":"tenant=test;field=shared;version=1","subject_mode":"stored","authenticated":authenticated}
            profiles.append(profile)
        ctx.config_data["fpe_profiles"].extend(profiles)
        key, key_hash=create_api_key_pair()
        ctx.config_data["permissions"].append({"client":"fpe-only-subject","apikey_hash":key_hash,"status":"active","permissions":[{"kid":kid,"actions":["fpe-encrypt","fpe-decrypt"]}]})
        ctx.write_config(); ctx.reload_config()
        app=StatusClient(ctx.base_url,key)
        create={"profile":creator["name"],"subject_name":"shared-user"}
        subject=ctx.client.post(f"/subject/{kid}",create,auth=True)["subject"]
        other=ctx.client.post(f"/subject/{kid}",dict(create,subject_name="other-user"),auth=True)["subject"]
        token=ctx.client.post(f"/token/encode/{kid}/subject/{subject}",{"ref":"token","profile":creator["name"],"plaintext":"synthetic shared data"},auth=True)["token"]
        token_inverse={"ref":"token","kid":kid,"profile":creator["name"],"subject":subject,"token":token}
        require(ctx.client.post("/token/decode",token_inverse,auth=True)["plaintext"]=="synthetic shared data","same subject still works with tokens")
        saved=[]
        for profile in profiles:
            body={"ref":"fpe","profile":profile["name"],"plaintext":"001-234"}
            route=f"/fpe/encrypt/{kid}/subject/{subject}"
            status, output=app.post(route,body,auth=True)
            require(status==200 and output["subject"]==subject,"FPE-only permission opens original token seed")
            require(("tag" in output)==profile["authenticated"],"subject mode is independent of authentication")
            inverse={"ref":"new-ref","kid":kid,"profile":profile["name"],"subject":subject,"ciphertext":output["ciphertext"]}
            if "tag" in output: inverse["tag"]=output["tag"]
            require(app.post("/fpe/decrypt",inverse,auth=True)==(200,{"ref":"new-ref","plaintext":"001-234"}),"subject FPE exact round trip")
            missing=dict(inverse); missing.pop("subject")
            require(app.post("/fpe/decrypt",missing,auth=True)[0]==400,"stored decrypt requires subject")
            require(app.post("/fpe/decrypt",dict(inverse,subject=None),auth=True)[0]==400,"null subject rejected")
            require(app.post(f"/fpe/encrypt/{kid}",body,auth=True)[0]==400,"stored profile rejects legacy route")
            if profile["authenticated"]:
                require(app.post("/fpe/decrypt",dict(inverse,subject=other),auth=True)==(400,{"error":"fpe authentication failed"}),"different subject fails authentication")
            batch={"profile":profile["name"],"items":[{"ref":"a","plaintext":"001-234"},{"ref":"b","plaintext":"567-890"}]}
            status, output=app.post(f"/fpe/encrypt/batch/{kid}/subject/{subject}",batch,auth=True)
            require(status==200 and output["subject"]==subject,"batch shares one subject")
            status, decoded=app.post("/fpe/decrypt/batch",{"kid":kid,"profile":profile["name"],"subject":subject,"items":output["items"]},auth=True)
            require(status==200 and [item["plaintext"] for item in decoded["items"]]==["001-234","567-890"],"subject batch order")
            saved.append(inverse)
        # The original creator is resolved from signed config, not request parameters.
        ctx.config_data["tokenization_profiles"].remove(creator)
        ctx.write_config(); ctx.reload_config()
        require(app.post("/fpe/decrypt",saved[1],auth=True)==(500,{"error":"internal server error"}),"missing creator config fails closed")
        ctx.config_data["tokenization_profiles"].append(creator)
        creator["subject_mode"]="none"
        ctx.write_config(); ctx.reload_config()
        require(app.post("/fpe/decrypt",saved[1],auth=True)==(500,{"error":"internal server error"}),"incompatible creator policy fails closed")
        creator["subject_mode"]="stored"
        ctx.write_config(); ctx.reload_config()
        require(ctx.http._request("DELETE",f"/subject/{kid}/{subject}",auth=True)[0]==204,"subject deletion unchanged")
        for inverse in saved:
            require(app.post("/fpe/decrypt",inverse,auth=True)[0]==404,"deleted seed blocks all future FPE")
        require(ctx.http.post("/token/decode",token_inverse,auth=True)[0]==404,"deleted seed blocks tokens")
        recreated=ctx.client.post(f"/subject/{kid}",create,auth=True)["subject"]
        require(recreated==subject,"recreated subject retains ID")
        require(app.post("/fpe/decrypt",saved[1],auth=True)==(400,{"error":"fpe authentication failed"}),"recreated seed cannot authenticate old ciphertext")
        body={"ref":"fresh","profile":profiles[1]["name"],"plaintext":"001-234"}
        status, fresh=app.post(f"/fpe/encrypt/{kid}/subject/{subject}",body,auth=True)
        require(status==200,"recreated subject encrypts with fresh keys")
        fresh_inverse={"ref":"fresh","kid":kid,"subject":subject,"profile":profiles[1]["name"],"ciphertext":fresh["ciphertext"],"tag":fresh["tag"]}
        ctx.client.post(f"/lifecycle/{kid}",{"status":"retired","reason":"subject FPE test"},auth=True)
        require(app.post("/fpe/decrypt",fresh_inverse,auth=True)[0]==200,"retired subject decrypt works")
        require(app.post(f"/fpe/encrypt/{kid}/subject/{subject}",body,auth=True)[0]==403,"retired subject encrypt blocked")
        print("- FPE/token shared subjects, creator binding, batch and erasure: OK",flush=True)
        return CaseResult()
    finally:
        ctx.config_data=original
        ctx.write_config(); ctx.reload_config()


CASES=cases.tuple()
