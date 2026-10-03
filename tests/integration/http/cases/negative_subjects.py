"""Subject request boundaries and strict signed profile modes."""
import copy

from lib.assertions import require
from lib.casekit import CaseSet
from lib.fixtures import create_key
from lib.results import CaseResult
from .negative_support import require_config_sign_fails

cases = CaseSet()


@cases("negative.tokenization.subject-boundaries")
def run_subject_boundaries(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        kid = create_key(ctx.client, {"tag": "subject-negative", "profile": "hybrid-performance-v1"})
        profile = {"name": "subjects-boundaries-v1", "kid": kid, "token_prefix": "tok_subject",
            "token_len": 32, "max_plaintext_len": 128, "one_time": False, "subject_mode": "stored"}
        ctx.config_data["tokenization_profiles"].append(profile)
        ctx.write_config()
        ctx.reload_config()
        body = {"profile": profile["name"], "subject_name": "synthetic"}
        require(ctx.http.post(f"/subject/{kid}", body, auth=False)[0] == 401, "create requires authentication")
        for name in ["", "  ", "x" * 129, "界" * 129, "x;y", "x=y", "x\n", 42, None]:
            status, output = ctx.http.post(f"/subject/{kid}", dict(body, subject_name=name), auth=True)
            require(status == 400 and "subject" not in output, "invalid subject_name rejected")
        for field in ["seed", "cipher", "subject_mode", "extra"]:
            require(ctx.http.post(f"/subject/{kid}", dict(body, **{field: "invalid"}), auth=True)[0] == 400, "unknown field rejected")
        for field in ["profile", "subject_name"]:
            missing = dict(body)
            missing.pop(field)
            require(ctx.http.post(f"/subject/{kid}", missing, auth=True)[0] == 400, "required field")
        for name in ["x" * 128, "界" * 128]:
            status, output = ctx.http.post(f"/subject/{kid}", dict(body, subject_name=name), auth=True)
            require(status == 201 and len(output["subject"]) == 64, "Unicode limit inclusive")
        token_body = {"ref": "invalid-subject", "kid": kid, "profile": profile["name"], "token": "tok_subject_" + "A" * 43}
        for subject in ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, 42]:
            for path in ["/token/decode", "/token/delete"]:
                require(ctx.http.post(path, dict(token_body, subject=subject), auth=True)[0] == 400, "invalid subject encoding")
        for mode in ["derived", "STORED", True, None]:
            profile["subject_mode"] = mode
            ctx.write_config(sign=False)
            require_config_sign_fails("invalid subject_mode")
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
