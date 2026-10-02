{{- define "demo-helm.image" -}}
{{- if .Values.image.ref }}{{ .Values.image.ref }}{{ else }}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{ end }}
{{- end -}}
