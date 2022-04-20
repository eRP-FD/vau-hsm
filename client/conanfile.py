#!/usr/bin/env python3

###################################################################################################

# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

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

    _verbose_cmake_argument = 'VERBOSE'

    _cmake = None

    _test_build_requires = ['gtest/1.11.0',
                            'openssl/1.1.1k']

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
                'compiler': ['gcc', 'Visual Studio'],
                'build_type': ['Debug', 'Release', 'RelWithDebInfo'],
                'arch': ['x86', 'x86_64']}

    generators = ['cmake']

    exports_sources = ['CMakeLists.txt',
                       'cmake/*',
                       'src/*',
                       'test/*']

    build_requires = ['asn1c/0.9.29']

    requires = ['csxapi/1.0']

    def _get_cmake(self):
        if self._cmake:
            return self._cmake

        self._cmake = CMake(self, set_cmake_flags=True)

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
            self.version = git.run('describe --all --exclude "v-*" --match "v*"')[6:]

    def requirements(self):
        if self.options.with_tests:
            self.build_requires += self._test_build_requires

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
