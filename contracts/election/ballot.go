// This file is a generated binding and any manual changes will be lost.

package election

import (
	"math/big"
	"strings"

	"github.com/hpb-project/go-hpb/account/abi/bind"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/account/abi"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

// BallotABI is the input ABI used to generate the binding from.
const BallotABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"proposal\",\"type\":\"uint256\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"proposals\",\"outputs\":[{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"voteCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"chairperson\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"to\",\"type\":\"address\"}],\"name\":\"delegate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winningProposal\",\"outputs\":[{\"name\":\"winningProposal_\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"giveRightToVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voters\",\"outputs\":[{\"name\":\"weight\",\"type\":\"uint256\"},{\"name\":\"voted\",\"type\":\"bool\"},{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"vote\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winnerName\",\"outputs\":[{\"name\":\"winnerName_\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"proposalNames\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// BallotBin is the compiled bytecode used for deploying new contracts.
const BallotBin = `0x608060405234801561001057600080fd5b506040516107df3803806107df833981016040908152815160008054600160a060020a0319163317808255600160a060020a031681526001602081905292812092909255909101905b81518110156100bc5760026040805190810160405280848481518110151561007d57fe5b60209081029091018101518252600091810182905283546001818101865594835291819020835160029093020191825591909101519082015501610059565b5050610712806100cd6000396000f30060806040526004361061008d5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416630121b93f8114610092578063013cf08b146100ac5780632e4176cf146100dd5780635c19a95c1461010e578063609ff1bd1461012f5780639e7b8d6114610156578063a3ec138d14610177578063e2ba53f0146101c6575b600080fd5b34801561009e57600080fd5b506100aa6004356101db565b005b3480156100b857600080fd5b506100c4600435610290565b6040805192835260208301919091528051918290030190f35b3480156100e957600080fd5b506100f26102bc565b60408051600160a060020a039092168252519081900360200190f35b34801561011a57600080fd5b506100aa600160a060020a03600435166102cb565b34801561013b57600080fd5b506101446104de565b60408051918252519081900360200190f35b34801561016257600080fd5b506100aa600160a060020a0360043516610548565b34801561018357600080fd5b50610198600160a060020a0360043516610685565b604080519485529215156020850152600160a060020a03909116838301526060830152519081900360800190f35b3480156101d257600080fd5b506101446106b9565b3360009081526001602081905260409091209081015460ff1615610249576040805160e560020a62461bcd02815260206004820152600e60248201527f416c726561647920766f7465642e000000000000000000000000000000000000604482015290519081900360640190fd5b6001818101805460ff191690911790556002808201839055815481549091908490811061027257fe5b60009182526020909120600160029092020101805490910190555050565b600280548290811061029e57fe5b60009182526020909120600290910201805460019091015490915082565b600054600160a060020a031681565b33600090815260016020819052604082209081015490919060ff161561033b576040805160e560020a62461bcd02815260206004820152601260248201527f596f7520616c726561647920766f7465642e0000000000000000000000000000604482015290519081900360640190fd5b600160a060020a03831633141561039c576040805160e560020a62461bcd02815260206004820152601e60248201527f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e0000604482015290519081900360640190fd5b600160a060020a03838116600090815260016020819052604090912001546101009004161561044957600160a060020a039283166000908152600160208190526040909120015461010090049092169133831415610444576040805160e560020a62461bcd02815260206004820152601960248201527f466f756e64206c6f6f7020696e2064656c65676174696f6e2e00000000000000604482015290519081900360640190fd5b61039c565b506001818101805460ff1916821774ffffffffffffffffffffffffffffffffffffffff001916610100600160a060020a0386169081029190911790915560009081526020829052604090209081015460ff16156104d1578154600282810154815481106104b257fe5b60009182526020909120600160029092020101805490910190556104d9565b815481540181555b505050565b600080805b60025481101561054357816002828154811015156104fd57fe5b906000526020600020906002020160010154111561053b57600280548290811061052357fe5b90600052602060002090600202016001015491508092505b6001016104e3565b505090565b600054600160a060020a031633146105d0576040805160e560020a62461bcd02815260206004820152602860248201527f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742060448201527f746f20766f74652e000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b600160a060020a0381166000908152600160208190526040909120015460ff1615610645576040805160e560020a62461bcd02815260206004820152601860248201527f54686520766f74657220616c726561647920766f7465642e0000000000000000604482015290519081900360640190fd5b600160a060020a0381166000908152600160205260409020541561066857600080fd5b600160a060020a0316600090815260016020819052604090912055565b600160208190526000918252604090912080549181015460029091015460ff8216916101009004600160a060020a03169084565b600060026106c56104de565b815481106106cf57fe5b9060005260206000209060020201600001549050905600a165627a7a723058206390618b4e207e98e82dafc2592901b49041cebdf0530a98e9c75f0921f0b40f0029`

// DeployBallot deploys a new Ethereum contract, binding an instance of Ballot to it.
func DeployBallot(auth *bind.TransactOpts, backend bind.ContractBackend, proposalNames [][32]byte) (common.Address, *types.Transaction, *Ballot, error) {
	parsed, err := abi.JSON(strings.NewReader(BallotABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(BallotBin), backend, proposalNames)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Ballot{BallotCaller: BallotCaller{contract: contract}, BallotTransactor: BallotTransactor{contract: contract}}, nil
}

// Ballot is an auto generated Go binding around an Ethereum contract.
type Ballot struct {
	BallotCaller     // Read-only binding to the contract
	BallotTransactor // Write-only binding to the contract
}

// BallotCaller is an auto generated read-only Go binding around an Ethereum contract.
type BallotCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BallotTransactor is an auto generated write-only Go binding around an Ethereum contract.
type BallotTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BallotSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type BallotSession struct {
	Contract     *Ballot           // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// BallotCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type BallotCallerSession struct {
	Contract *BallotCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// BallotTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type BallotTransactorSession struct {
	Contract     *BallotTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// BallotRaw is an auto generated low-level Go binding around an Ethereum contract.
type BallotRaw struct {
	Contract *Ballot // Generic contract binding to access the raw methods on
}

// BallotCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type BallotCallerRaw struct {
	Contract *BallotCaller // Generic read-only contract binding to access the raw methods on
}

// BallotTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type BallotTransactorRaw struct {
	Contract *BallotTransactor // Generic write-only contract binding to access the raw methods on
}

// NewBallot creates a new instance of Ballot, bound to a specific deployed contract.
func NewBallot(address common.Address, backend bind.ContractBackend) (*Ballot, error) {
	contract, err := bindBallot(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Ballot{BallotCaller: BallotCaller{contract: contract}, BallotTransactor: BallotTransactor{contract: contract}}, nil
}

// NewBallotCaller creates a new read-only instance of Ballot, bound to a specific deployed contract.
func NewBallotCaller(address common.Address, caller bind.ContractCaller) (*BallotCaller, error) {
	contract, err := bindBallot(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &BallotCaller{contract: contract}, nil
}

// NewBallotTransactor creates a new write-only instance of Ballot, bound to a specific deployed contract.
func NewBallotTransactor(address common.Address, transactor bind.ContractTransactor) (*BallotTransactor, error) {
	contract, err := bindBallot(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &BallotTransactor{contract: contract}, nil
}

// bindBallot binds a generic wrapper to an already deployed contract.
func bindBallot(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(BallotABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ballot *BallotRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ballot.Contract.BallotCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ballot *BallotRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Ballot.Contract.BallotTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ballot *BallotRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Ballot.Contract.BallotTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ballot *BallotCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ballot.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ballot *BallotTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Ballot.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ballot *BallotTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Ballot.Contract.contract.Transact(opts, method, params...)
}

// Chairperson is a free data retrieval call binding the contract method 0x2e4176cf.
//
// Solidity: function chairperson() constant returns(address)
func (_Ballot *BallotCaller) Chairperson(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Ballot.contract.Call(opts, out, "chairperson")
	return *ret0, err
}

// Chairperson is a free data retrieval call binding the contract method 0x2e4176cf.
//
// Solidity: function chairperson() constant returns(address)
func (_Ballot *BallotSession) Chairperson() (common.Address, error) {
	return _Ballot.Contract.Chairperson(&_Ballot.CallOpts)
}

// Chairperson is a free data retrieval call binding the contract method 0x2e4176cf.
//
// Solidity: function chairperson() constant returns(address)
func (_Ballot *BallotCallerSession) Chairperson() (common.Address, error) {
	return _Ballot.Contract.Chairperson(&_Ballot.CallOpts)
}

// Proposals is a free data retrieval call binding the contract method 0x013cf08b.
//
// Solidity: function proposals( uint256) constant returns(name bytes32, voteCount uint256)
func (_Ballot *BallotCaller) Proposals(opts *bind.CallOpts, arg0 *big.Int) (struct {
	Name      [32]byte
	VoteCount *big.Int
}, error) {
	ret := new(struct {
		Name      [32]byte
		VoteCount *big.Int
	})
	out := ret
	err := _Ballot.contract.Call(opts, out, "proposals", arg0)
	return *ret, err
}

// Proposals is a free data retrieval call binding the contract method 0x013cf08b.
//
// Solidity: function proposals( uint256) constant returns(name bytes32, voteCount uint256)
func (_Ballot *BallotSession) Proposals(arg0 *big.Int) (struct {
	Name      [32]byte
	VoteCount *big.Int
}, error) {
	return _Ballot.Contract.Proposals(&_Ballot.CallOpts, arg0)
}

// Proposals is a free data retrieval call binding the contract method 0x013cf08b.
//
// Solidity: function proposals( uint256) constant returns(name bytes32, voteCount uint256)
func (_Ballot *BallotCallerSession) Proposals(arg0 *big.Int) (struct {
	Name      [32]byte
	VoteCount *big.Int
}, error) {
	return _Ballot.Contract.Proposals(&_Ballot.CallOpts, arg0)
}

// Voters is a free data retrieval call binding the contract method 0xa3ec138d.
//
// Solidity: function voters( address) constant returns(weight uint256, voted bool, delegate address, vote uint256)
func (_Ballot *BallotCaller) Voters(opts *bind.CallOpts, arg0 common.Address) (struct {
	Weight   *big.Int
	Voted    bool
	Delegate common.Address
	Vote     *big.Int
}, error) {
	ret := new(struct {
		Weight   *big.Int
		Voted    bool
		Delegate common.Address
		Vote     *big.Int
	})
	out := ret
	err := _Ballot.contract.Call(opts, out, "voters", arg0)
	return *ret, err
}

// Voters is a free data retrieval call binding the contract method 0xa3ec138d.
//
// Solidity: function voters( address) constant returns(weight uint256, voted bool, delegate address, vote uint256)
func (_Ballot *BallotSession) Voters(arg0 common.Address) (struct {
	Weight   *big.Int
	Voted    bool
	Delegate common.Address
	Vote     *big.Int
}, error) {
	return _Ballot.Contract.Voters(&_Ballot.CallOpts, arg0)
}

// Voters is a free data retrieval call binding the contract method 0xa3ec138d.
//
// Solidity: function voters( address) constant returns(weight uint256, voted bool, delegate address, vote uint256)
func (_Ballot *BallotCallerSession) Voters(arg0 common.Address) (struct {
	Weight   *big.Int
	Voted    bool
	Delegate common.Address
	Vote     *big.Int
}, error) {
	return _Ballot.Contract.Voters(&_Ballot.CallOpts, arg0)
}

// WinnerName is a free data retrieval call binding the contract method 0xe2ba53f0.
//
// Solidity: function winnerName() constant returns(winnerName_ bytes32)
func (_Ballot *BallotCaller) WinnerName(opts *bind.CallOpts) ([32]byte, error) {
	var (
		ret0 = new([32]byte)
	)
	out := ret0
	err := _Ballot.contract.Call(opts, out, "winnerName")
	return *ret0, err
}

// WinnerName is a free data retrieval call binding the contract method 0xe2ba53f0.
//
// Solidity: function winnerName() constant returns(winnerName_ bytes32)
func (_Ballot *BallotSession) WinnerName() ([32]byte, error) {
	return _Ballot.Contract.WinnerName(&_Ballot.CallOpts)
}

// WinnerName is a free data retrieval call binding the contract method 0xe2ba53f0.
//
// Solidity: function winnerName() constant returns(winnerName_ bytes32)
func (_Ballot *BallotCallerSession) WinnerName() ([32]byte, error) {
	return _Ballot.Contract.WinnerName(&_Ballot.CallOpts)
}

// WinningProposal is a free data retrieval call binding the contract method 0x609ff1bd.
//
// Solidity: function winningProposal() constant returns(winningProposal_ uint256)
func (_Ballot *BallotCaller) WinningProposal(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Ballot.contract.Call(opts, out, "winningProposal")
	return *ret0, err
}

// WinningProposal is a free data retrieval call binding the contract method 0x609ff1bd.
//
// Solidity: function winningProposal() constant returns(winningProposal_ uint256)
func (_Ballot *BallotSession) WinningProposal() (*big.Int, error) {
	return _Ballot.Contract.WinningProposal(&_Ballot.CallOpts)
}

// WinningProposal is a free data retrieval call binding the contract method 0x609ff1bd.
//
// Solidity: function winningProposal() constant returns(winningProposal_ uint256)
func (_Ballot *BallotCallerSession) WinningProposal() (*big.Int, error) {
	return _Ballot.Contract.WinningProposal(&_Ballot.CallOpts)
}

// Delegate is a paid mutator transaction binding the contract method 0x5c19a95c.
//
// Solidity: function delegate(to address) returns()
func (_Ballot *BallotTransactor) Delegate(opts *bind.TransactOpts, to common.Address) (*types.Transaction, error) {
	return _Ballot.contract.Transact(opts, "delegate", to)
}

// Delegate is a paid mutator transaction binding the contract method 0x5c19a95c.
//
// Solidity: function delegate(to address) returns()
func (_Ballot *BallotSession) Delegate(to common.Address) (*types.Transaction, error) {
	return _Ballot.Contract.Delegate(&_Ballot.TransactOpts, to)
}

// Delegate is a paid mutator transaction binding the contract method 0x5c19a95c.
//
// Solidity: function delegate(to address) returns()
func (_Ballot *BallotTransactorSession) Delegate(to common.Address) (*types.Transaction, error) {
	return _Ballot.Contract.Delegate(&_Ballot.TransactOpts, to)
}

// GiveRightToVote is a paid mutator transaction binding the contract method 0x9e7b8d61.
//
// Solidity: function giveRightToVote(voter address) returns()
func (_Ballot *BallotTransactor) GiveRightToVote(opts *bind.TransactOpts, voter common.Address) (*types.Transaction, error) {
	return _Ballot.contract.Transact(opts, "giveRightToVote", voter)
}

// GiveRightToVote is a paid mutator transaction binding the contract method 0x9e7b8d61.
//
// Solidity: function giveRightToVote(voter address) returns()
func (_Ballot *BallotSession) GiveRightToVote(voter common.Address) (*types.Transaction, error) {
	return _Ballot.Contract.GiveRightToVote(&_Ballot.TransactOpts, voter)
}

// GiveRightToVote is a paid mutator transaction binding the contract method 0x9e7b8d61.
//
// Solidity: function giveRightToVote(voter address) returns()
func (_Ballot *BallotTransactorSession) GiveRightToVote(voter common.Address) (*types.Transaction, error) {
	return _Ballot.Contract.GiveRightToVote(&_Ballot.TransactOpts, voter)
}

// Vote is a paid mutator transaction binding the contract method 0x0121b93f.
//
// Solidity: function vote(proposal uint256) returns()
func (_Ballot *BallotTransactor) Vote(opts *bind.TransactOpts, proposal *big.Int) (*types.Transaction, error) {
	return _Ballot.contract.Transact(opts, "vote", proposal)
}

// Vote is a paid mutator transaction binding the contract method 0x0121b93f.
//
// Solidity: function vote(proposal uint256) returns()
func (_Ballot *BallotSession) Vote(proposal *big.Int) (*types.Transaction, error) {
	return _Ballot.Contract.Vote(&_Ballot.TransactOpts, proposal)
}

// Vote is a paid mutator transaction binding the contract method 0x0121b93f.
//
// Solidity: function vote(proposal uint256) returns()
func (_Ballot *BallotTransactorSession) Vote(proposal *big.Int) (*types.Transaction, error) {
	return _Ballot.Contract.Vote(&_Ballot.TransactOpts, proposal)
}
