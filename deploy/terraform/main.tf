# Example: deploy Aether IoT/OT Security into an existing Kubernetes cluster
# with a managed PostgreSQL database. Adjust providers to your platform.

terraform {
  required_providers {
    helm       = { source = "hashicorp/helm", version = "~> 2.13" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.30" }
    random     = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "kubeconfig" { type = string }
variable "namespace" { default = "aether" }
variable "database_url" {
  type        = string
  sensitive   = true
  description = "postgres://aether_iot:...@host:5432/aether_iot (role must be NOSUPERUSER NOBYPASSRLS)"
}
variable "platform_url" { type = string }
variable "public_url" { type = string }
variable "client_id" { type = string }
variable "client_secret" {
  type      = string
  sensitive = true
}
variable "image_tag" { default = "0.1.0" }

provider "kubernetes" { config_path = var.kubeconfig }
provider "helm" {
  kubernetes { config_path = var.kubeconfig }
}

# 32-byte data-encryption key, version 1 (add versions to rotate: "1:...,2:...").
resource "random_bytes" "dek" { length = 32 }

resource "kubernetes_secret" "iot" {
  metadata {
    name      = "aether-iot-ot"
    namespace = var.namespace
  }
  data = {
    "database-url"    = var.database_url
    "encryption-keys" = "1:${random_bytes.dek.base64}"
    "client-id"       = var.client_id
    "client-secret"   = var.client_secret
  }
}

resource "helm_release" "iot" {
  name       = "aether-iot-ot"
  namespace  = var.namespace
  chart      = "${path.module}/../helm/aether-iot-ot"
  depends_on = [kubernetes_secret.iot]
  values = [yamlencode({
    image    = { tag = var.image_tag }
    platform = { url = var.platform_url, issuer = var.platform_url }
    config   = { publicUrl = var.public_url }
    ingress  = { enabled = true, host = replace(var.public_url, "https://", "") }
  })]
}
