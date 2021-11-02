## HSM Firmware

#### Design Notes

- Siehe vau-hsm/Design.md für Kommentare zum Design.

#### Pre-build steps

- es muss ein `SSH` Key erzeugt werden und der öffentlicher Teil zu Ihrem [GitHub account](https://github.ibmgcloud.net/settings/keys) hinzugefügt werden. Eine Anleitung dazu finden Sie [hier](https://docs.github.com/en/github/authenticating-to-github/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).

#### How to build on Linux

- Installieren der Abhängigkeiten: `conan`, `cmake`, `make`, `gcc`, `libc6-dev-i386`

- Fügen Sie die eRP Conan Repositories von Nexus hinzu: `conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal`

- Optional: Wenn Sie Conan zum ersten Mal installiert haben und es für ein C++>=11-Projekt verwenden wollen, führen Sie außerdem folgende Schritte aus: `conan profile update settings.compiler.libcxx=libstdc++11 default`

- Aktualisieren Sie Ihr (vielleicht `default`) Conan-Profil für den richtigen Build-Typ (`Debug` oder `Release`): `conan profile update settings.build_type=Debug default`

- Erstellen Sie einen Build-Ordner für den richtigen Build-Typ: mkdir build-debug

- Wechseln Sie das Arbeitsverzeichnis in den neu erstellten Ordner und rufen Sie CMake mit dem richtigen Build-Typ auf: `cmake -DCMAKE_BUILD_TYPE=Debug ..`

- Bauen Sie das Projekt: `make -j4`

- Artefakte können im Build-Ordner unter `lib` gefunden werden

- Der HSM-Simulator befindet sich im Build-Ordner unter `Simulator`

#### How to build on Windows

- Microsoft Visual Studio 2019 ist die einzige Toolchain, die unterstützt wird. Andere Versionen können auch funktionieren.

- Installieren Sie Conan von [here](https://conan.io/downloads.html) (per Installer oder per `pip`, beide Optionen sollten funktionieren)

- Vergewissern Sie sich, dass Conan korrekt installiert und zu Ihrem `PATH` hinzugefügt wurde

- Erstellen Sie ein neues Conan-Profil: `conan profil new default --detect`

- Aktualisieren Sie Ihr neu hinzugefügtes Profil für den richtigen Build-Typ (`Debug` oder `Release`): `conan profile update settings.build_type=Debug default`

- Öffnen Sie den Ordner `firmware` in Visual Studio. Öffnen Sie nicht Root `vau-hsm`, sondern nur die `firmware`.

- VS sollte CMake automatisch aufrufen und Sie sollten in der Lage sein, die Lösung von der Benutzeroberfläche aus zu erstellen, sowohl im "Debug"- als auch im "Release"-Modus

- Artefakte können im Build-Ordner unter `bin` gefunden werden

- Der HSM-Simulator befindet sich im Build-Ordner unter `Simulator`

#### How to use with CLion

Die Integration mit `CLion` funktioniert ebenfalls, ohne (zu viel) Aufwand, die einzigen Dinge, die zu beachten sind, sind ein paar Anpassungen unter `Settings` > `Build, Execution, Deployment` > `CMake`:
- Erstellung von zwei Profilen (über das kleine `+` Symbol): `Debug` und `Release`
- Für jedes Profil setzen Sie (entsprechend) die `CMake Options` auf `-DCMAKE_BUILD_TYPE=Debug` und das `Build directory` auf `build-debug`
- Optional können die `Build options` für beide Profile auf `-- -j 4` gesetzt werden
