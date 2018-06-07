# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: ghpb android ios ghpb-cross swarm evm all test clean
.PHONY: ghpb-linux ghpb-linux-386 ghpb-linux-amd64 ghpb-linux-mips64 ghpb-linux-mips64le
.PHONY: ghpb-linux-arm ghpb-linux-arm-5 ghpb-linux-arm-6 ghpb-linux-arm-7 ghpb-linux-arm64
.PHONY: ghpb-darwin ghpb-darwin-386 ghpb-darwin-amd64
.PHONY: ghpb-windows ghpb-windows-386 ghpb-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

ghpb:
	build/env.sh go run build/ci.go install ./command/ghpb
	@echo "Done building."
	@echo "Run \"$(GOBIN)/ghpb\" to launch ghpb."

bootnode:
	build/env.sh go run build/ci.go install ./command/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/bootnode\" to launch bootnode."

promfile:
	build/env.sh go run build/ci.go install ./command/promfile
	@echo "Done building."
	@echo "Run \"$(GOBIN)/promfile\" to launch promfile."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/ghpb.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Ghpb.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/jteeuwen/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go install ./command/abigen

# Cross Compilation Targets (xgo)

ghpb-cross: ghpb-linux ghpb-darwin ghpb-windows ghpb-android ghpb-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-*

ghpb-linux: ghpb-linux-386 ghpb-linux-amd64 ghpb-linux-arm ghpb-linux-mips64 ghpb-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-*

ghpb-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./command/ghpb
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep 386

ghpb-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./command/ghpb
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep amd64

bootnode-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./command/bootnode
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep amd64

ghpb-linux-arm: ghpb-linux-arm-5 ghpb-linux-arm-6 ghpb-linux-arm-7 ghpb-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep arm

ghpb-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./command/ghpb
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep arm-5

ghpb-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./command/ghpb
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep arm-6

ghpb-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./command/ghpb
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep arm-7

ghpb-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./command/ghpb
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep arm64

ghpb-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./command/ghpb
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep mips

ghpb-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./command/ghpb
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep mipsle

ghpb-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./command/ghpb
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep mips64

ghpb-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./command/ghpb
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-linux-* | grep mips64le

ghpb-darwin: ghpb-darwin-386 ghpb-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-darwin-*

ghpb-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./command/ghpb
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-darwin-* | grep 386

ghpb-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./command/ghpb
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-darwin-* | grep amd64

ghpb-windows: ghpb-windows-386 ghpb-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-windows-*

ghpb-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./command/ghpb
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-windows-* | grep 386

ghpb-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./command/ghpb
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ghpb-windows-* | grep amd64