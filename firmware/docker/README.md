### Building `hsm-firmware` in a Docker container

`hsm-firmware` is buildable in a Docker container (and runnable as well).

The Docker image is built by the `build` script (written in Bash).

Run `./build --help` from this directory in order to see usage indications (arguments, options, etc) for the script.

The script needs Nexus credentials in order to feed them to Conan for when retrieving the firmware dependencies.

A private SSH key (whose public part is registered in your GitHub account) is also necessary for the cloning of the relevant repositories.

Example of running the `build` script:
```
./build --image-name vau-hsm-firmware --nexus-username john.doe --nexus-password myPassword --ssh-key /home/user/.ssh/id_rsa
```

After the image has been built successfully, you can run it using `docker run -it <image-name>`. This will start the simulator in a container on port 3001 locally. You need to export this port (append `-p OUTSIDE_PORT:3001` to the `docker run` command) if you want to access the simulator from outside the container.

#### Building the Docker image from Windows with WSL2

Follow the [instructions](https://docs.docker.com/docker-for-windows/wsl) for the WSL2 kernel update and then installing a WSL2 Linux distribution.

From outside the WSL, at a Windows command line, run:
```    
wsl --list --verbose
wsl --set-version <distro name from previous list> 2
```

If needed, mount Windows drives from within the WSL by running:
```
sudo mkdir /mnt/d
sudo mount -t drvfs d: /mnt/d
```

Then simply navigate to this directory (`vau-hsm/firmware/docker`) from within WSL and use the `./build` script as you would if you were natively running Linux.
