## Guide to start dockerized BitVMX client services

1. **Configure your local SSH Key**  
   You should have access to private GitHub Repos.

2. **Edit `.env` file**  
   You can set your personalized config.

3. **Build the Docker images:**
   ```sh
   docker compose build
   ```
   > If your Docker does not have BuildKit activated by default, add the following environment variable to your local session:
   > `export DOCKER_BUILDKIT=1`

4. **Start all services:**
   ```sh
   docker compose up
   ```

5. **Choose the operator**  
   Edit `CLIENT_OP` in `.env` and run step 4 or execute:
   ```sh
   CLIENT_OP=op_2 docker compose up
   ```