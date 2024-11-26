{ stdenv, pkgs, lib }:

pkgs.stdenv.mkDerivation rec {
  name = "cros-ectool";
  nativeBuildInputs = with pkgs; [ cmake ninja pkg-config libusb1 libftdi1 ];
  src = builtins.fetchGit {
    url = "git@github.com:Xelef2000/ectool.git";
    rev = "a734465bdd16e6b535b080aeafb72461cfadc3f2";
    allRefs = true;
    };
  installPhase = ''
    mkdir -p $out/bin
    cp src/ectool $out/bin/ectool
  '';
  meta = with lib; {
    description = "ectool for ChromeOS devices";
    homepage = "https://gitlab.howett.net/DHowett/ectool";
    license = licenses.bsd3;
    maintainers = with maintainers; [ ChocolateLoverRaj ];
    platforms = platforms.linux;
    mainProgram = "ectool";
  };
}
