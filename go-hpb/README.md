## Go HPB

Official golang implementation of the HPB protocol.

[![API Reference](
https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667
)](#)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](#)



## Building the source

Building ghpb requires both a Go (version 1.7 or later)

    git clone git@github.com:hpb-project/go-hpb-private.git $GOPATH/src/github.com/hpb-project

then

    go install -a -v ./cmd/ghpb

## Running ghpb
```
$ ghpb --identity "private hpb"  --rpcaddr 127.0.0.1  --rpc   --rpcport 8545  --maxpeers 2  --networkid 100  --datadir "./chain"  --nodiscover
```

## Starting JavaScript Console
```
ghpb attach ipc://path-to-chain-directory/ghpb.ipc
```
### Develop

#### 修改web3.js后需要重新生成bindata.go文件，使用go-bindata命令，安装该命令
```
go get -u github.com/jteeuwen/go-bindata/...
```

#### 重新生成bindata.go文件 在GoPath/src/github.com/hpb-project/go-hpb/internal/jsre/deps执行
```
go-bindata -nometadata -pkg deps -o bindata.go bignumber.js web3.js
```

#### 格式化bindata.go 在GoPath/src/github.com/hpb-project/go-hpb/internal/jsre/deps执行
```
gofmt -w -s bindata.go
```

#### 重新构建后生效
```
go install -a -v ./cmd/ghpb
```