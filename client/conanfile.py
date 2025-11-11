###################################################################################################

# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

###################################################################################################

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.env import VirtualBuildEnv, VirtualRunEnv
from conan.tools.scm import Git

required_conan_version = ">=1.53.0"


class HsmClientPackage(ConanFile):
    name = "hsmclient"
    url = "https://github.ibmgcloud.net/eRp/vau-hsm"
    homepage = "https://github.ibmgcloud.net/eRp/vau-hsm/"
    description = "The VAU HSM client access library"
    license = "proprietary"
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "verbose": [True, False],
        "with_tests": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "verbose": False,
        "with_tests": False,
        "asn1c/*:silent": False,
        "asn1c/*:with_unit_tests": False,
        "gtest/*:build_gmock": False,
        "gtest/*:shared": True,
        "csxapi/*:shared": True,
    }
    exports_sources = ["CMakeLists.txt", "cmake/*", "src/*", "test/*"]

    @property
    def _min_cppstd(self):
        return 17

    @property
    def _compilers_minimum_version(self):
        return {
            "gcc": "7",
            "clang": "7",
            "apple-clang": "10",
        }

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def requirements(self):
        self.requires("csxapi/1.0")
        self.requires("asn1c/cci.20200522")
        if self.options.with_tests:
            self.test_requires("gtest/1.15.0")
            self.test_requires("openssl/[>=1.1 <4]")

    def build_requirements(self):
        self.tool_requires("asn1c/cci.20200522")
        self.tool_requires("cmake/[>=3.18 <4]")

    def layout(self):
        cmake_layout(self)

    def validate(self):
        if self.settings.compiler.cppstd:
            check_min_cppstd(self, self._min_cppstd)
        if self.settings.os != "Windows" and self.options.verbose:
            raise ConanInvalidConfiguration('Option "verbose" only works on Windows due to csxapi')

    def generate(self):
        run_env = VirtualRunEnv(self)
        run_env.generate(scope="build")
        tc = CMakeToolchain(self)
        # do not run clang-tidy
        tc.variables["WITHOUT_CLANG_TIDY"] = True
        tc.variables["BUILD_TESTING"] = self.options.with_tests
        if self.options.verbose:
            tc.variables["VERBOSE"] = True
        tc.variables["CONAN_ASN1C_ROOT"] = self.dependencies["asn1c"].package_folder
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()

        build_env = VirtualBuildEnv(self)
        build_env.generate(scope="build")

        # for dep in self.dependencies.values():
        #     copy(self, "*.dll", dep.cpp_info.libdirs[0], self.build_folder)

    def set_version(self):
        if not self.version:
            git = Git(self, folder=self.recipe_folder)
            self.version = git.run('describe --tags --abbrev=0 --match "v-[0-9\.]*"')[2:].lower()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

        # run the tests if option was given
        #
        if self.options.with_tests:
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["hsmclient"]


###################################################################################################
