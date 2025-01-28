use bollard::Docker;
use bollard::container::{Config, RemoveContainerOptions, StopContainerOptions};
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerCreateResponse, HostConfig};
use bollard::errors::Error;
use std::default::Default;
use tokio::runtime::Runtime;
use tracing::{self, info};

pub struct Bitcoind {
    docker: Docker,
    container_name: String,
    image: String,
    runtime: Runtime,
}

impl Bitcoind {
    pub fn new(container_name: &str, image: &str) -> Self {
        Bitcoind {
            docker: Docker::connect_with_local_defaults().unwrap(),
            container_name: container_name.to_string(),
            image: image.to_string(),
            runtime: Runtime::new().unwrap(),
        }
    }

    pub fn start(&self) -> Result<(), Error> {
        self.runtime.block_on(async {
            if self.is_running().await? {
                self.stop()?;
            }

            self.create_and_start_container().await?;
            Ok(())
        })
    }

    pub fn stop(&self) -> Result<(), Error> {
        self.runtime.block_on(async {
            if self.is_running().await? {
                self.docker
                    .stop_container(&self.container_name, None::<StopContainerOptions>)
                    .await?;
                self.docker
                    .remove_container(&self.container_name, Some(RemoveContainerOptions { force: true, ..Default::default() }))
                    .await?;
            }
            Ok(())
        })
    }

    async fn is_running(&self) -> Result<bool, Error> {
        let containers = self.docker.list_containers(None::<bollard::container::ListContainersOptions<String>>).await?;
        for container in containers {
            if let Some(names) = container.names {
                if names.contains(&self.container_name) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }


    async fn create_and_start_container(&self) -> Result<(), Error> {
        let config = Config {
            image: Some(self.image.clone()),
            host_config: Some(HostConfig {
                auto_remove: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ContainerCreateResponse { id, .. } = self.docker.create_container::<&str, String>(None, config).await?;
        self.docker.start_container::<String>(&id, None).await?;
        Ok(())
    }
}