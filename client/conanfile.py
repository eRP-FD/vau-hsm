#!/usr/bin/env python3

###################################################################################################

# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

###################################################################################################

from conans import CMake
from conans import ConanFile
from conans import tools
from conans.errors import ConanException

###################################################################################################

import os
import shutil
import stat

###################################################################################################

class HsmClientPackage(ConanFile):

    # custom properties for usage by this specific recipe's code, not by the Conan SDK

    _build_tests_cmake_argument = 'BUILD_TESTS'

    _no_clang_tidy_cmake_argument = 'WITHOUT_CLANG_TIDY'

    _verbose_cmake_argument = 'VERBOSE'

    _cmake = None

    # Conan properties, used by the Conan SDK

    name = 'hsmclient'

    homepage = 'https://github.ibmgcloud.net/eRp/vau-hsm/tree/master/client'

    description = 'The VAU HSM client access library'

    author = 'Theodor Serbana <theodor.serbana@ibm.com>'

    license = 'proprietary'

    url = 'https://github.ibmgcloud.net/eRp/vau-hsm'

    options = {'verbose': [True, False],
               'with_tests': [True, False]}

    default_options = {'verbose': False,
                       'with_tests': False,
                       'asn1c:silent': False,
                       'asn1c:with_unit_tests': False,
                       'gtest:build_gmock': False,
                       'gtest:shared': True,
                       'csxapi:shared': True}

    settings = {'os': ['Linux', 'Windows'],
                'compiler': ['gcc', 'clang', 'Visual Studio'],
                'build_type': ['Debug', 'Release', 'RelWithDebInfo'],
                'arch': ['x86', 'x86_64']}

    generators = ['cmake']

    exports_sources = ['CMakeLists.txt',
                       'cmake/*',
                       'src/*',
                       'test/*']

    def _get_cmake(self):
        if self._cmake:
            return self._cmake

        self._cmake = CMake(self, set_cmake_flags=True)

        # do not run clang-tidy
        #
        self._cmake.definitions[self._no_clang_tidy_cmake_argument] = 1

        # build the tests if option was given
        #
        if self.options.with_tests:
            self._cmake.definitions[self._build_tests_cmake_argument] = 1

        # define verbose flag if option was given
        #
        if self.options.verbose:
            if not tools.os_info.is_windows:
                raise ConanException('Option "verbose" only works on Windows due to csxapi')

            self._cmake.definitions[self._verbose_cmake_argument] = 1

        # call cmake configure
        #
        self._cmake.configure()
        return self._cmake

    def set_version(self):
        if not self.version:
            git = tools.Git()
            self.version = git.run('describe --tags --abbrev=0 --match "v-[0-9\.]*"')[2:]

    def requirements(self):
        self.requires("csxapi/1.0")
        self.requires("asn1c/cci.20200522")
        if self.options.with_tests:
            self.requires("gtest/1.15.0")
            self.requires("openssl/1.1.1k")

    def build(self):
        # build the source code
        #
        cmake = self._get_cmake()
        cmake.build()

        # run the tests if option was given
        #
        if self.options.with_tests:
            cmake.test()

    def package(self):
        # call the CMake install target
        #
        cmake = self._get_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)

    def imports(self):
        self.copy('*.dll', 'bin', 'bin')
        self.copy('*.so*', 'lib', 'lib', root_package='csxapi')

###################################################################################################
