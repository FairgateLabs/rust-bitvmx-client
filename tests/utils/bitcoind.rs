use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};
use bollard::errors::Error;
use bollard::models::{ContainerCreateResponse, HostConfig};
use bollard::Docker;
use std::default::Default;
use tokio::runtime::Runtime;
use tracing::{self, info};
pub struct Bitcoind {
    docker: Docker,
    container_name: String,
    image: String,
    runtime: Runtime,
    rpc_config: RpcConfig,
}

impl Bitcoind {
    pub fn new(container_name: &str, image: &str, rpc_config: &RpcConfig) -> Self {
        Bitcoind {
            docker: Docker::connect_with_local_defaults().unwrap(),
            container_name: container_name.to_string(),
            image: image.to_string(),
            runtime: Runtime::new().unwrap(),
            rpc_config: rpc_config.clone(),
        }
    }

    pub fn start(&self) -> Result<(), Error> {
        self.runtime.block_on(async {
            self.internal_stop().await?;
            self.create_and_start_container().await?;
            Ok(())
        })
    }

    async fn internal_stop(&self) -> Result<(), Error> {
        if self.is_running().await? {
            info!("Container was running. Stopping bitcoind container");
            self.docker
                .remove_container(
                    &self.container_name,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await?;
            for _ in 0..10 {
                if !self.is_running().await? {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                info!("Waiting for bitcoind container to stop");
            }
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<(), Error> {
        info!("Stopping bitcoind container");
        self.runtime.block_on(async {
            self.internal_stop().await?;
            Ok(())
        })
    }

    async fn is_running(&self) -> Result<bool, Error> {
        let containers = self
            .docker
            .list_containers(None::<bollard::container::ListContainersOptions<String>>)
            .await?;
        for container in containers {
            if let Some(names) = container.names {
                if names.contains(&format!("/{}", self.container_name)) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn create_and_start_container(&self) -> Result<(), Error> {
        info!("Creating and starting bitcoind container");
        let config = Config {
            image: Some(self.image.clone()),
            env: Some(vec!["BITCOIN_DATA=/data".to_string()]),
            host_config: Some(HostConfig {
                auto_remove: Some(true),
                port_bindings: Some(
                    [(
                        //TODO: Parse port from url
                        "18443/tcp".to_string(),
                        Some(vec![bollard::service::PortBinding {
                            host_ip: Some("0.0.0.0".to_string()),
                            host_port: Some("18443".to_string()),
                        }]),
                    )]
                    .iter()
                    .cloned()
                    .collect(),
                ),
                ..Default::default()
            }),
            cmd: Some(vec![
                "-regtest=1".to_string(),
                "-printtoconsole".to_string(),
                "-rpcallowip=0.0.0.0/0".to_string(),
                "-rpcbind=0.0.0.0".to_string(),
                format!("-rpcuser={}", self.rpc_config.username).to_string(),
                format!("-rpcpassword={}", self.rpc_config.password).to_string(),
                "-server=1".to_string(),
                "-txindex=1".to_string(),
                "-fallbackfee=0.0002".to_string(),
            ]),
            ..Default::default()
        };
        let ContainerCreateResponse { id, .. } = self
            .docker
            .create_container::<&str, String>(
                Some(CreateContainerOptions {
                    name: &self.container_name,
                }),
                config,
            )
            .await?;
        self.docker.start_container::<String>(&id, None).await?;
        Ok(())
    }
}
