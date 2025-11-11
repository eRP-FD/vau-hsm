# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH


from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.env import VirtualBuildEnv, VirtualRunEnv

class HsmFirmwarePackage(ConanFile):
    name = "hsmfirmware"
    url = "https://github.ibmgcloud.net/eRp/vau-hsm"
    homepage = "https://github.ibmgcloud.net/eRp/vau-hsm/"
    description = "The VAU HSM firmware"
    license = "proprietary"
    package_type = "application"
    settings = "os", "arch", "compiler", "build_type"

    exports_sources = ["CMakeLists.txt", "cmake/*", "src/*"]

    def requirements(self):
        self.requires("cryptoserversdk/2.0")

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.16 <4]")

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def generate(self):
        run_env = VirtualRunEnv(self)
        run_env.generate(scope="build")
        tc = CMakeToolchain(self)
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()

        build_env = VirtualBuildEnv(self)
        build_env.generate(scope="build")

        cryptosdk_root = self.dependencies["cryptoserversdk"].cpp_info.bindirs[0] + '/../'
        for d in ["bin", "devices", "keys"]:
            copy(self, "*", cryptosdk_root + d, self.build_folder + f'/simulator/{d}')
