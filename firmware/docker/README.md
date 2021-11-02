### Building `hsm-firmware` in a Docker container

`hsm-firmware` is buildable in a Docker container (and runnable as well).

The Docker image is built by the `build` script (written in Bash).

Run `./build --help` from this directory in order to see usage indications (arguments, options, etc) for the script.

The script needs Nexus credentials in order to feed them to Conan for when retrieving the firmware dependencies.

A private SSH key (whose public part is registered in your GitHub account) is also necessary for the cloning of the relevant repositories.

Building with Windows and WSL 2
--------------------------------
Follow instructions for the WSL 2 kernel update and then installing a WSL2 linux distribution.   https://docs.docker.com/docker-for-windows/wsl/
Ubuntu 20.04 LTS is known to work.
From outside the wsl at a windows command line run:
	wsl --list --verbose
	wsl --set-version <distro name from previous list> 2
If needed mount windows drives with:
	sudo mkdir /mnt/d
	sudo mount -t drvfs d: /mnt/d
Assuming Conan and docker were already setup on the windows system then they should work within the WSL.
Copy your ssh private key to ~/.ssh/id_rsa
Go to thwe firmware/docker directory in the vau-hs, repo.
run ./build --help`
The actual run could be something like this:
./build  --image-name vau-hsm-sim  --nexus-username <nnn.nnn> --nexus-password <pwd.pwd>

Then, once complete, run:
	docker run -t vau-hsm-sim
This will start the sim on port 3001 locally.   Add -p nnnn:3001 to the line above to expose the HSM Sim on a different port nnnn
