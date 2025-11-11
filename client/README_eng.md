## HSM Client Access Library

#### Design Notes

- See vau-hsm/Design.md for design commentaries.

#### Pre-build steps

- an `SSH` key must be generated and its public part added to your [GitHub account](https://github.ibmgcloud.net/settings/keys). Instructions for doing so you can find [here](https://docs.github.com/en/github/authenticating-to-github/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).


#### How to build on Linux

- install dependencies: `conan`, `cmake`, `make`, `gcc`

- add the eRP Conan repository from artifactory: `conan remote add erp-conan-2 https://artifactory-cpp-ce.ihc-devops.net/artifactory/api/conan/erp-conan-2`

- optional: if you installed Conan for the first time and plan to use it for any C++>=11 project, also do the following: `conan profile update settings.compiler.libcxx=libstdc++11 default`

- update your (perhaps `default`) Conan profile for the right build type (`Debug` or `Release`): `conan profile update settings.build_type=Debug default`

- Run the first part of the build step with:

  `conan install . --output-folder build-debug --build=missing -s build_type=Debug|Release|RelWithDebInfo -o with_tests=True|False`

  The `with_tests` argument is optional and defaults to `False`.
- Run the second part of the build step with:

  `cmake -GNinja -Bbuild -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo && cmake --build build`


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

The build folder can be opened as project in CLion. That way, build and run settings are already determined and nothing else has to be set up.
