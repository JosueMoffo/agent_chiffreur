//! Crate partagé GANDAL — protobuf (tonic) et configuration mTLS.

pub mod tls;

pub mod proto {
    tonic::include_proto!("gandal.v1");
}

pub use proto::{
    auditeur_service_client::AuditeurServiceClient,
    auditeur_service_server::{AuditeurService, AuditeurServiceServer},
    chiffreur_service_client::ChiffreurServiceClient,
    chiffreur_service_server::{ChiffreurService, ChiffreurServiceServer},
    proxy_chiffreur_service_client::ProxyChiffreurServiceClient,
    proxy_chiffreur_service_server::{ProxyChiffreurService, ProxyChiffreurServiceServer},
    AuditeurEvent, Empty, EventAck, HealthResponse, ProxyAnnounceRequest, ProxyAnnounceResponse,
    RegistryStatusResponse, RotateRequest, RotateResponse, VmSyncRequest, VmSyncResponse,
    RotateProxyResult,
};
