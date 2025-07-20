{ pkgs, ... }:

{
  languages.go = { enable = true; };

  packages = with pkgs; [ air golangci-lint go-mockery ];

}
