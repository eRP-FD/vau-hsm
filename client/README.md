## HSM Client Access Library


#### Pre-build steps

- a `SSH` key must be generated and its public part added to your [GitHub account](https://github.ibmgcloud.net/settings/keys). Instructions for doing so you can find [here](https://docs.github.com/en/github/authenticating-to-github/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).


#### How to build on Linux

- install dependencies: `conan`, `cmake`, `make`, `gcc`

- add the eRP Conan repository from Nexus: `conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal`

- optional: if you installed Conan for the first time and plan to use it for any C++>=11 project, also do the following: `conan profile update settings.compiler.libcxx=libstdc++11 default`

- update your (perhaps `default`) Conan profile for the right build type (`Debug` or `Release`): `conan profile update settings.build_type=Debug default`

- create a build folder for the right build type: `mkdir build-debug`

- change working directory into the newly created folder and invoke CMake with the right build type: `cmake -DCMAKE_BUILD_TYPE=Debug ..`

- build the project: `make -j4`

- artefacts can be found in the build folder under `lib`


#### How to build on Windows

- Microsoft Visual Studio 2019 is the only toolchain supported. Other versions might work too.

- install Conan from [here](https://conan.io/downloads.html) (via installer or via `pip`, both options should be fine)

- make sure Conan is installed correctly and added to your `PATH`

- create a fresh Conan profile: `conan profile new default --detect`

- update your newly added profile for the right build type (`Debug` or `Release`): `conan profile update settings.build_type=Debug default`

- open up this `client` folder in Visual Studio. Do not open the root `vau-hsm`, but only the `client`.

- VS should invoke CMake automatically and you should be able to build the solution from the UI, both in `Debug` or in `Release` mode

- artefacts can be found in the build folder under `bin`


#### How to use with CLion

Integration with `CLion` works too, without (too much of a) hassle, the only things nice to have being couple adjustments under `Settings` > `Build, Execution, Deployment` > `CMake`:
- create two profiles (from the small `+` icon): `Debug` and `Release`
- for each profile, set (accordingly) the `CMake Options` to `-DCMAKE_BUILD_TYPE=Debug` and the `Build directory` to `build-debug`
- optionally, `Build options` can be set for both profiles to `-- -j 4`
