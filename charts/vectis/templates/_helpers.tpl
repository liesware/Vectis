{{- define "vectis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vectis.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "vectis.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vectis.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "vectis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "vectis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vectis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vectis.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-runtime" (include "vectis.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "vectis.validate" -}}
{{- if ne .Values.vectis.storage "postgres" -}}
{{- fail "Vectis Helm chart supports only PostgreSQL storage; set vectis.storage=postgres" -}}
{{- end -}}
{{- if not (has .Values.vectis.mode (list "dev" "prod")) -}}
{{- fail "vectis.mode must be dev or prod" -}}
{{- end -}}
{{- if and (eq .Values.vectis.mode "prod") (not .Values.vectis.tls.enabled) -}}
{{- fail "vectis.tls.enabled must be true when vectis.mode=prod" -}}
{{- end -}}
{{- end -}}
