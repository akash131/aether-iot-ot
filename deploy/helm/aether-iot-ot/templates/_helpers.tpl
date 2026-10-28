{{- define "iot.name" -}}aether-iot-ot{{- end -}}
{{- define "iot.labels" -}}
app.kubernetes.io/name: {{ include "iot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "iot.env" -}}
- name: IOT_ENV
  value: production
- name: IOT_LOG_JSON
  value: "1"
- name: IOT_RUN_MIGRATIONS
  value: "false"
- name: IOT_PUBLIC_URL
  value: {{ .Values.config.publicUrl | quote }}
- name: AETHER_PLATFORM_URL
  value: {{ .Values.platform.url | quote }}
- name: AETHER_ISSUER
  value: {{ .Values.platform.issuer | quote }}
- name: AETHER_AUDIENCE
  value: {{ .Values.platform.audience | quote }}
- name: IOT_DB_MAX_CONNECTIONS
  value: {{ .Values.config.dbMaxConnections | quote }}
- name: IOT_INGEST_CONCURRENCY
  value: {{ .Values.config.ingestConcurrency | quote }}
- name: IOT_RATE_LIMIT_PER_MINUTE
  value: {{ .Values.config.rateLimitPerMinute | quote }}
- name: IOT_OBSERVATION_RETENTION_DAYS
  value: {{ .Values.config.observationRetentionDays | quote }}
- name: IOT_HISTORY_RETENTION_DAYS
  value: {{ .Values.config.historyRetentionDays | quote }}
{{- with .Values.config.dataRegion }}
- name: IOT_DATA_REGION
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.branchUrl }}
- name: IOT_BRANCH_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.privateAccessUrl }}
- name: IOT_PRIVATE_ACCESS_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.firewallUrl }}
- name: IOT_FIREWALL_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.vulnFeedUrl }}
- name: IOT_VULN_FEED_URL
  value: {{ . | quote }}
{{- end }}
- name: IOT_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: database-url } }
- name: IOT_ENCRYPTION_KEYS
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: encryption-keys } }
- name: IOT_CLIENT_ID
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: client-id } }
- name: IOT_CLIENT_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: client-secret } }
{{- end -}}
