
package election

import (
	"math/big"
	"strings"

	"github.com/hpb-project/go-hpb/account/abi/bind"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/blockchain/types"

	"github.com/hpb-project/go-hpb/account/abi"
)

// HpbballotABI is the input ABI used to generate the binding from.
const HpbballotABI = "[{\"constant\":false,\"inputs\":[],\"name\":\"voteResult\",\"outputs\":[{\"name\":\"addr\",\"type\":\"address[]\"},{\"name\":\"_facilityIds\",\"type\":\"bytes32[]\"},{\"name\":\"nums\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"endBlock\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_name\",\"type\":\"bytes32\"},{\"name\":\"_startBlock\",\"type\":\"uint256\"},{\"name\":\"_endBlock\",\"type\":\"uint256\"},{\"name\":\"_minAmount\",\"type\":\"uint256\"},{\"name\":\"_capacity\",\"type\":\"uint256\"},{\"name\":\"_version\",\"type\":\"uint256\"}],\"name\":\"changeVotingBlocks\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"candidateIndexMapAddrs\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"beginVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"MAX_UINT256\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"facilityIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"candidateArray\",\"outputs\":[{\"name\":\"candidateAddr\",\"type\":\"address\"},{\"name\":\"balance\",\"type\":\"uint256\"},{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"facilityId\",\"type\":\"bytes32\"},{\"name\":\"numberOfVotes\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"startBlock\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"capacity\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"votesNumArray\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"hasReleaseAmount\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"candidateIndexMap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voterIndexMap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"payDepositByCandidate\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"candidateAddr\",\"type\":\"address\"}],\"name\":\"fechVoteInfoForVoterByCandidateAddr\",\"outputs\":[{\"name\":\"nums\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"minAmount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"candidateAddr\",\"type\":\"address\"}],\"name\":\"voteBySendHpb\",\"outputs\":[{\"name\":\"serialNumber\",\"type\":\"uint256\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"fechVoteInfoForCandidate\",\"outputs\":[{\"name\":\"addrs\",\"type\":\"address[]\"},{\"name\":\"nums\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voterAddr\",\"type\":\"address\"}],\"name\":\"fechVoteInfoForCandidateByVoterAddr\",\"outputs\":[{\"name\":\"nums\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"fechVoteResultForCandidate\",\"outputs\":[{\"name\":\"num\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidateAddr\",\"type\":\"address\"}],\"name\":\"deleteCandidates\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"endVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"releaseAmount\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"voterArray\",\"outputs\":[{\"name\":\"voterAddr\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidateAddr\",\"type\":\"address\"},{\"name\":\"_facilityId\",\"type\":\"bytes32\"},{\"name\":\"_name\",\"type\":\"bytes32\"}],\"name\":\"AddCandidate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"fechVoteInfoForVoter\",\"outputs\":[{\"name\":\"addrs\",\"type\":\"address[]\"},{\"name\":\"nums\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"_name\",\"type\":\"bytes32\"},{\"name\":\"_startBlock\",\"type\":\"uint256\"},{\"name\":\"_endBlock\",\"type\":\"uint256\"},{\"name\":\"_minAmount\",\"type\":\"uint256\"},{\"name\":\"_capacity\",\"type\":\"uint256\"},{\"name\":\"_version\",\"type\":\"uint256\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"constructor\"},{\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"fallback\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"serialNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"facilityId\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"candidateAddr\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"name\",\"type\":\"bytes32\"}],\"name\":\"CandidateAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"VoteAddr\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"serialNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"facilityId\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"candidateAddr\",\"type\":\"address\"}],\"name\":\"Voted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"name\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"startBlock\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"endBlock\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"minAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"capacity\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"version\",\"type\":\"uint256\"}],\"name\":\"ChangeOfBlocks\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"receivedEther\",\"type\":\"event\"}]"

// HpbballotBin is the compiled bytecode used for deploying new contracts.
const HpbballotBin = `0x7f48504242616c6c6f7400000000000000000000000000000000000000000000006001908155600060028190556003819055600491909155600581905568056bc75e2d63100000600b55600c805460ff19169055608081905260a060408190526200006e916017919062000193565b5060408051600081526020810191829052516200008e91601891620001e3565b506040805160008152602081019182905251620000ae9160199162000249565b506040805160008152602081019182905251620000ce91601a9162000193565b5060405160c080620025848339810160408181528251602080850151838601516060808801516080808a015160a09a8b015160008054600160a060020a03191633179055600189905560028790556003869055600b84905560058290556004819055888b52968a01869052888a018590529289018290528801829052978701849052945193969195909491939192917fecf2d1f22b8b389f8293a2059f9cbbce8336cf24def816ccecdb48914578dc329181900360c00190a1505050505050620002d0565b828054828255906000526020600020908101928215620001d1579160200282015b82811115620001d1578251825591602001919060010190620001b4565b50620001df92915062000289565b5090565b8280548282559060005260206000209081019282156200023b579160200282015b828111156200023b5782518254600160a060020a031916600160a060020a0390911617825560209092019160019091019062000204565b50620001df929150620002a9565b828054828255906000526020600020908101928215620001d1579160200282015b82811115620001d157825182556020909201916001909101906200026a565b620002a691905b80821115620001df576000815560010162000290565b90565b620002a691905b80821115620001df578054600160a060020a0319168155600101620002b0565b6122a480620002e06000396000f3006080604052600436106101895763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416623259ea81146101c557806306fdde03146102b8578063083c6323146102df57806313a2f4a0146102f457806313a3a7f31461031d57806328bc5ee41461035157806333a581d214610366578063342d8d7e1461037b57806335a893a11461039357806348cd4cb1146103e057806354fd4d50146103f55780635cfc1a511461040a578063725f66a61461041f578063760234351461043757806381f4bf85146104605780638da5cb5b14610481578063903a0e6c14610496578063927731c8146104b75780639ab744e6146104bf5780639b2cb5d8146104e05780639dc5b6df146104f55780639eace9bd14610509578063a1a1d72c146105b7578063a4adc431146105d8578063abe6c54d146105ed578063b92239461461060e578063c062dc5f14610623578063c279919f14610638578063c767c18f14610650578063e47d914a14610677578063f2fde38b1461068c575b6040805133815234602082015281517fa398b89ba344a0b23a0b9de53db298b2a1a868b396c1878b7e9dcbafecd49b13929181900390910190a1005b3480156101d157600080fd5b506101da6106ad565b60405180806020018060200180602001848103845287818151815260200191508051906020019060200280838360005b8381101561022257818101518382015260200161020a565b50505050905001848103835286818151815260200191508051906020019060200280838360005b83811015610261578181015183820152602001610249565b50505050905001848103825285818151815260200191508051906020019060200280838360005b838110156102a0578181015183820152602001610288565b50505050905001965050505050505060405180910390f35b3480156102c457600080fd5b506102cd610d4a565b60408051918252519081900360200190f35b3480156102eb57600080fd5b506102cd610d50565b34801561030057600080fd5b5061031b60043560243560443560643560843560a435610d56565b005b34801561032957600080fd5b50610335600435610de8565b60408051600160a060020a039092168252519081900360200190f35b34801561035d57600080fd5b5061031b610e10565b34801561037257600080fd5b506102cd610e2d565b34801561038757600080fd5b506102cd600435610e33565b34801561039f57600080fd5b506103ab600435610e52565b60408051600160a060020a03909616865260208601949094528484019290925260608401526080830152519081900360a00190f35b3480156103ec57600080fd5b506102cd610e9b565b34801561040157600080fd5b506102cd610ea1565b34801561041657600080fd5b506102cd610ea7565b34801561042b57600080fd5b506102cd600435610ead565b34801561044357600080fd5b5061044c610ebb565b604080519115158252519081900360200190f35b34801561046c57600080fd5b506102cd600160a060020a0360043516610ec4565b34801561048d57600080fd5b50610335610ed6565b3480156104a257600080fd5b506102cd600160a060020a0360043516610ee5565b61031b610ef7565b3480156104cb57600080fd5b506102cd600160a060020a036004351661105d565b3480156104ec57600080fd5b506102cd6110e5565b6102cd600160a060020a03600435166110eb565b34801561051557600080fd5b5061051e611128565b604051808060200180602001838103835285818151815260200191508051906020019060200280838360005b8381101561056257818101518382015260200161054a565b50505050905001838103825284818151815260200191508051906020019060200280838360005b838110156105a1578181015183820152602001610589565b5050505090500194505050505060405180910390f35b3480156105c357600080fd5b506102cd600160a060020a03600435166112a4565b3480156105e457600080fd5b506102cd611329565b3480156105f957600080fd5b5061031b600160a060020a0360043516611385565b34801561061a57600080fd5b5061031b611605565b34801561062f57600080fd5b5061031b611622565b34801561064457600080fd5b5061033560043561174a565b34801561065c57600080fd5b5061031b600160a060020a0360043516602435604435611777565b34801561068357600080fd5b5061051e611a34565b34801561069857600080fd5b5061031b600160a060020a0360043516611ba4565b6060806060600080600080600354431115156106c857600080fd5b6018600760008154811015156106da57fe5b600091825260208083209091015483546001810185559383529082209092018054600160a060020a031916600160a060020a039093169290921790915586516019918891811061072657fe5b6020908102909101810151825460018101845560009384529183209091015560088054601a9290811061075557fe5b600091825260208083209091015483546001810185559383529082209092019190915560088054909190811061078757fe5b9060005260206000200154935060009250600191505b600a5460001901821015610c2957600c5460ff16151561095757816001141561088b576000600a60008154811015156107d257fe5b906000526020600020906008020160010154111561088b57600a805460009081106107f957fe5b60009182526020822060089091020154600a8054600160a060020a03909216926108fc92811061082557fe5b9060005260206000209060080201600101549081150290604051600060405180830381858888f19350505050158015610862573d6000803e3d6000fd5b506000600a600081548110151561087557fe5b9060005260206000209060080201600101819055505b6000600a8381548110151561089c57fe5b906000526020600020906008020160010154111561095757600a8054839081106108c257fe5b6000918252602090912060089091020154600a8054600160a060020a03909216916108fc9190859081106108f257fe5b9060005260206000209060080201600101549081150290604051600060405180830381858888f1935050505015801561092f573d6000803e3d6000fd5b506000600a8381548110151561094157fe5b9060005260206000209060080201600101819055505b6005548211610a8857601780546001810182556000919091527fc624b66cc0138b8fabc209247f72d758e1cf3343756d543badbf24212bed8c15018290556007805460189190849081106109a757fe5b6000918252602080832090910154835460018101855593835291209091018054600160a060020a031916600160a060020a0390921691909117905585516019908790849081106109f357fe5b60209081029091018101518254600181018455600093845291909220015560088054601a919084908110610a2357fe5b600091825260208083209091015483546001810185559383529120909101556008805485919084908110610a5357fe5b90600052602060002001541015610a83576008805483908110610a7257fe5b906000526020600020015493508192505b610c1e565b83600883815481101515610a9857fe5b90600052602060002001541115610c1e5781601784815481101515610ab957fe5b6000918252602090912001556007805483908110610ad357fe5b60009182526020909120015460188054600160a060020a039092169185908110610af957fe5b9060005260206000200160006101000a815481600160a060020a030219169083600160a060020a031602179055508582815181101515610b3557fe5b90602001906020020151601984815481101515610b4e57fe5b6000918252602090912001556008805483908110610b6857fe5b9060005260206000200154601a84815481101515610b8257fe5b9060005260206000200181905550600090505b60175460001901811015610c1e57836008601783815481101515610bb557fe5b9060005260206000200154815481101515610bcc57fe5b90600052602060002001541015610c16576008601782815481101515610bee57fe5b9060005260206000200154815481101515610c0557fe5b906000526020600020015493508092505b600101610b95565b60019091019061079d565b600c805460ff191660011790556018805460408051602080840282018101909252828152601992601a92859190830182828015610c8f57602002820191906000526020600020905b8154600160a060020a03168152600190910190602001808311610c71575b5050505050925081805480602002602001604051908101604052809291908181526020018280548015610ce257602002820191906000526020600020905b81548152600190910190602001808311610ccd575b5050505050915080805480602002602001604051908101604052809291908181526020018280548015610d3457602002820191906000526020600020905b815481526020019060010190808311610d20575b5050505050905096509650965050505050909192565b60015481565b60035481565b600054600160a060020a03163314610d6d57600080fd5b600186905560028590556003849055600b839055600582905560048190556040805187815260208101879052808201869052606081018590526080810184905260a0810183905290517fecf2d1f22b8b389f8293a2059f9cbbce8336cf24def816ccecdb48914578dc329181900360c00190a1505050505050565b6007805482908110610df657fe5b600091825260209091200154600160a060020a0316905081565b600054600160a060020a03163314610e2757600080fd5b43600255565b60001981565b6009805482908110610e4157fe5b600091825260209091200154905081565b600a805482908110610e6057fe5b600091825260209091206008909102018054600182015460028301546003840154600490940154600160a060020a0390931694509092909185565b60025481565b60045481565b60055481565b6008805482908110610e4157fe5b600c5460ff1681565b60066020526000908152604090205481565b600054600160a060020a031681565b600d6020526000908152604090205481565b6000610f01611f88565b600354431115610f1057600080fd5b3360009081526006602052604081205492508211610f2d57600080fd5b600a805483908110610f3b57fe5b60009182526020918290206040805160e08101825260089093029091018054600160a060020a0316835260018101548385015260028101548383015260038101546060840152600481015460808401526006810180548351818702810187019094528084529394919360a086019392830182828015610fe357602002820191906000526020600020905b8154600160a060020a03168152600190910190602001808311610fc5575b505050505081526020016007820180548060200260200160405190810160405280929190818152602001828054801561103b57602002820191906000526020600020905b815481526020019060010190808311611027575b5050505050815250509050611054816020015134611bdd565b60209091015250565b6000806000600254431015151561107357600080fd5b336000908152600d6020526040902054915081151561109557600092506110de565b600e8054839081106110a357fe5b9060005260206000209060040201600101905080600085600160a060020a0316600160a060020a031681526020019081526020016000205492505b5050919050565b600b5481565b6000806000600254431015151561110157600080fd5b60035443111561111057600080fd5b5033905034611120848383611bf5565b949350505050565b6060806000806060806000600254431015151561114457600080fd5b336000908152600660205260408120549550851161116157600080fd5b600a80548690811061116f57fe5b90600052602060002090600802016005019350600a8581548110151561119157fe5b90600052602060002090600802016006018054806020026020016040519081016040528092919081815260200182805480156111f657602002820191906000526020600020905b8154600160a060020a031681526001909101906020018083116111d8575b505050505092508251604051908082528060200260200182016040528015611228578160200160208202803883390190505b509150600090505b600183510381101561129857836000848381518110151561124d57fe5b90602001906020020151600160a060020a0316600160a060020a0316815260200190815260200160002054828281518110151561128657fe5b60209081029091010152600101611230565b50909590945092505050565b600080600060025443101515156112ba57600080fd5b3360009081526006602052604090205491508115156112dc57600092506110de565b600a8054839081106112ea57fe5b9060005260206000209060080201600501905080600085600160a060020a0316600160a060020a031681526020019081526020016000205492506110de565b600080600254431015151561133d57600080fd5b503360009081526006602052604090205480151561135e5760009150611381565b600a80548290811061136c57fe5b90600052602060002090600802016004015491505b5090565b60008054600160a060020a0316331461139d57600080fd5b6003544311156113ac57600080fd5b600160a060020a03821660009081526006602052604090205415156113d057600080fd5b50600160a060020a0381166000908152600660205260409020545b600a546000190181101561152257600a80546001830190811061140a57fe5b9060005260206000209060080201600a8281548110151561142757fe5b6000918252602090912082546008909202018054600160a060020a031916600160a060020a0390921691909117815560018083015490820155600280830154908201556003808301549082015560048083015490820155600680830180546114929284019190611fd5565b50600782810180546114a79284019190612021565b509050506008816001018154811015156114bd57fe5b90600052602060002001546008828154811015156114d757fe5b60009182526020909120015560098054600183019081106114f457fe5b906000526020600020015460098281548110151561150e57fe5b6000918252602090912001556001016113eb565b600a8054600019810190811061153457fe5b6000918252602082206008909102018054600160a060020a0319168155600181018290556002810182905560038101829055600481018290559061157b600683018261206d565b61158960078301600061206d565b505060088054600019810190811061159d57fe5b60009182526020822001556009805460001981019081106115ba57fe5b6000918252602082200155600a8054906115d890600019830161208b565b5060088054906115ec9060001983016120b7565b5060098054906116009060001983016120b7565b505050565b600054600160a060020a0316331461161c57600080fd5b43600355565b60008054600160a060020a0316331461163a57600080fd5b600354431161164857600080fd5b600c5460ff1615156117475750600c805460ff1916600117905560005b600a5460001901811015611747576000600a8281548110151561168457fe5b906000526020600020906008020160010154111561173f57600a8054829081106116aa57fe5b6000918252602090912060089091020154600a8054600160a060020a03909216916108fc9190849081106116da57fe5b9060005260206000209060080201600101549081150290604051600060405180830381858888f19350505050158015611717573d6000803e3d6000fd5b506000600a8281548110151561172957fe5b9060005260206000209060080201600101819055505b600101611665565b50565b600e80548290811061175857fe5b6000918252602090912060049091020154600160a060020a0316905081565b600080546060908190600160a060020a0316331461179457600080fd5b6003544311156117a357600080fd5b600160a060020a038616600090815260066020526040902054925082151561184257600a54600160a060020a038716600090815260066020526040902081905592506117f0836001611bdd565b6117fb600a8261208b565b50611807836001611bdd565b6118126007826120b7565b5061181e836001611bdd565b6118296008826120b7565b50611835836001611bdd565b6118406009826120b7565b505b6040805160018082528183019092529060208083019080388339505060408051600180825281830190925292945090506020808301908038833901905050905060e06040519081016040528087600160a060020a031681526020016000815260200185600019168152602001866000191681526020016000815260200183815260200182815250600a848154811015156118d857fe5b60009182526020918290208351600892909202018054600160a060020a031916600160a060020a0390921691909117815582820151600182015560408301516002820155606083015160038201556080830151600482015560a08301518051919261194b926006850192909101906120db565b5060c08201518051611967916007840191602090910190612130565b5050600780548892508590811061197a57fe5b600091825260208220018054600160a060020a031916600160a060020a03939093169290921790915560088054859081106119b157fe5b9060005260206000200181905550846009848154811015156119cf57fe5b6000918252602091829020019190915560408051858152918201879052600160a060020a0388168282015260608201869052517f5913680fb7af451503841931179387085b087fc924d72f3c41db97a69872889f9181900360800190a1505050505050565b60608060008060608060006002544310151515611a5057600080fd5b336000908152600d602052604081205495508511611a6d57600080fd5b600e805486908110611a7b57fe5b90600052602060002090600402016001019350600e85815481101515611a9d57fe5b9060005260206000209060040201600201805480602002602001604051908101604052809291908181526020018280548015611b0257602002820191906000526020600020905b8154600160a060020a03168152600190910190602001808311611ae4575b505050505092508251604051908082528060200260200182016040528015611b34578160200160208202803883390190505b509150600090505b6001835103811015611298578360008483815181101515611b5957fe5b90602001906020020151600160a060020a0316600160a060020a03168152602001908152602001600020548282815181101515611b9257fe5b60209081029091010152600101611b3c565b600054600160a060020a03163314611bbb57600080fd5b60008054600160a060020a031916600160a060020a0392909216919091179055565b60008160001903831115611bf057600080fd5b500190565b60008060608060006002544310151515611c0e57600080fd5b600354431115611c1d57600080fd5b600160a060020a0388166000908152600660205260409020541515611c4157600080fd5b600160a060020a038816600090815260066020526040902054600a80549091908110611c6957fe5b600091825260209091206008909102018054600f8054600160a060020a031916600160a060020a039092169190911781556001820154601055600282015460115560038201546012556004820154601355600682018054611ccc91601591611fd5565b5060078281018054611ce19284019190612021565b5050600b5460105410159050611cf657600080fd5b601354611d039087611bdd565b6013819055600160a060020a038916600090815260066020526040902054600880549091908110611d3057fe5b6000918252602080832090910192909255600160a060020a0389168152601490915260409020541515611d7d57600160a060020a0387166000908152601460205260409020869055611dba565b600160a060020a038716600090815260146020526040902054611da09087611bdd565b600160a060020a0388166000908152601460205260409020555b600160a060020a0387166000908152600d60205260409020549350831515611e1457600e54600160a060020a0388166000908152600d602052604090208190559350611e07846001611bdd565b611e12600e8261216b565b505b6040805160008082526020820190815260a082018352600160a060020a038a169282019283526060820182905260808201819052600e80549296509094509086908110611e5d57fe5b60009182526020918290208351600492909202018054600160a060020a031916600160a060020a039092169190911781558282015180519192611ea8926002850192909101906120db565b5060408201518051611ec4916003840191602090910190612130565b50905050600e84815481101515611ed757fe5b60009182526020808320600160a060020a03808c1680865260148452604080872054928f168088526001600490970290940195909501808552958590209190915560125484519182529281018a905280840192909252606082015290519192507f6e96efa1259db9fe9cca16684ac4e1159d78c960532ab7e4f82931ae39eeb6c6919081900360800190a1600160a060020a0388166000908152600660205260409020549450505050509392505050565b60e0604051908101604052806000600160a060020a031681526020016000815260200160008019168152602001600080191681526020016000815260200160608152602001606081525090565b8280548282559060005260206000209081019282156120155760005260206000209182015b82811115612015578254825591600101919060010190611ffa565b50611381929150612197565b8280548282559060005260206000209081019282156120615760005260206000209182015b82811115612061578254825591600101919060010190612046565b506113819291506121be565b508054600082559060005260206000209081019061174791906121be565b8154818355818111156116005760080281600802836000526020600020918201910161160091906121d8565b815481835581811115611600576000838152602090206116009181019083016121be565b828054828255906000526020600020908101928215612015579160200282015b828111156120155782518254600160a060020a031916600160a060020a039091161782556020909201916001909101906120fb565b828054828255906000526020600020908101928215612061579160200282015b82811115612061578251825591602001919060010190612150565b815481835581811115611600576004028160040283600052602060002091820191016116009190612236565b6121bb91905b80821115611381578054600160a060020a031916815560010161219d565b90565b6121bb91905b8082111561138157600081556001016121c4565b6121bb91905b80821115611381578054600160a060020a031916815560006001820181905560028201819055600382018190556004820181905561221f600683018261206d565b61222d60078301600061206d565b506008016121de565b6121bb91905b80821115611381578054600160a060020a03191681556000612261600283018261206d565b61226f60038301600061206d565b5060040161223c5600a165627a7a7230582078fa63817487bd93abe3583277fe5a8d62d069bc2fbb37e1cdbe82e1b52eca070029`

// DeployHpbballot deploys a new Ethereum contract, binding an instance of Hpbballot to it.
func DeployHpbballot(auth *bind.TransactOpts, backend bind.ContractBackend, _name [32]byte, _startBlock *big.Int, _endBlock *big.Int, _minAmount *big.Int, _capacity *big.Int, _version *big.Int) (common.Address, *types.Transaction, *Hpbballot, error) {
	parsed, err := abi.JSON(strings.NewReader(HpbballotABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(HpbballotBin), backend, _name, _startBlock, _endBlock, _minAmount, _capacity, _version)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Hpbballot{HpbballotCaller: HpbballotCaller{contract: contract}, HpbballotTransactor: HpbballotTransactor{contract: contract}}, nil
}

// Hpbballot is an auto generated Go binding around an Ethereum contract.
type Hpbballot struct {
	HpbballotCaller     // Read-only binding to the contract
	HpbballotTransactor // Write-only binding to the contract
}

// HpbballotCaller is an auto generated read-only Go binding around an Ethereum contract.
type HpbballotCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HpbballotTransactor is an auto generated write-only Go binding around an Ethereum contract.
type HpbballotTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HpbballotSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type HpbballotSession struct {
	Contract     *Hpbballot        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// HpbballotCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type HpbballotCallerSession struct {
	Contract *HpbballotCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// HpbballotTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type HpbballotTransactorSession struct {
	Contract     *HpbballotTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// HpbballotRaw is an auto generated low-level Go binding around an Ethereum contract.
type HpbballotRaw struct {
	Contract *Hpbballot // Generic contract binding to access the raw methods on
}

// HpbballotCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type HpbballotCallerRaw struct {
	Contract *HpbballotCaller // Generic read-only contract binding to access the raw methods on
}

// HpbballotTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type HpbballotTransactorRaw struct {
	Contract *HpbballotTransactor // Generic write-only contract binding to access the raw methods on
}

// NewHpbballot creates a new instance of Hpbballot, bound to a specific deployed contract.
func NewHpbballot(address common.Address, backend bind.ContractBackend) (*Hpbballot, error) {
	contract, err := bindHpbballot(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Hpbballot{HpbballotCaller: HpbballotCaller{contract: contract}, HpbballotTransactor: HpbballotTransactor{contract: contract}}, nil
}

// NewHpbballotCaller creates a new read-only instance of Hpbballot, bound to a specific deployed contract.
func NewHpbballotCaller(address common.Address, caller bind.ContractCaller) (*HpbballotCaller, error) {
	contract, err := bindHpbballot(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &HpbballotCaller{contract: contract}, nil
}

// NewHpbballotTransactor creates a new write-only instance of Hpbballot, bound to a specific deployed contract.
func NewHpbballotTransactor(address common.Address, transactor bind.ContractTransactor) (*HpbballotTransactor, error) {
	contract, err := bindHpbballot(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &HpbballotTransactor{contract: contract}, nil
}

// bindHpbballot binds a generic wrapper to an already deployed contract.
func bindHpbballot(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(HpbballotABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Hpbballot *HpbballotRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Hpbballot.Contract.HpbballotCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Hpbballot *HpbballotRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.Contract.HpbballotTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Hpbballot *HpbballotRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Hpbballot.Contract.HpbballotTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Hpbballot *HpbballotCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Hpbballot.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Hpbballot *HpbballotTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Hpbballot *HpbballotTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Hpbballot.Contract.contract.Transact(opts, method, params...)
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) MAX_UINT256(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "MAX_UINT256")
	return *ret0, err
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_Hpbballot *HpbballotSession) MAX_UINT256() (*big.Int, error) {
	return _Hpbballot.Contract.MAX_UINT256(&_Hpbballot.CallOpts)
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) MAX_UINT256() (*big.Int, error) {
	return _Hpbballot.Contract.MAX_UINT256(&_Hpbballot.CallOpts)
}

// CandidateArray is a free data retrieval call binding the contract method 0x35a893a1.
//
// Solidity: function candidateArray( uint256) constant returns(candidateAddr address, balance uint256, name bytes32, facilityId bytes32, numberOfVotes uint256)
func (_Hpbballot *HpbballotCaller) CandidateArray(opts *bind.CallOpts, arg0 *big.Int) (struct {
	CandidateAddr common.Address
	Balance       *big.Int
	Name          [32]byte
	FacilityId    [32]byte
	NumberOfVotes *big.Int
}, error) {
	ret := new(struct {
		CandidateAddr common.Address
		Balance       *big.Int
		Name          [32]byte
		FacilityId    [32]byte
		NumberOfVotes *big.Int
	})
	out := ret
	err := _Hpbballot.contract.Call(opts, out, "candidateArray", arg0)
	return *ret, err
}

// CandidateArray is a free data retrieval call binding the contract method 0x35a893a1.
//
// Solidity: function candidateArray( uint256) constant returns(candidateAddr address, balance uint256, name bytes32, facilityId bytes32, numberOfVotes uint256)
func (_Hpbballot *HpbballotSession) CandidateArray(arg0 *big.Int) (struct {
	CandidateAddr common.Address
	Balance       *big.Int
	Name          [32]byte
	FacilityId    [32]byte
	NumberOfVotes *big.Int
}, error) {
	return _Hpbballot.Contract.CandidateArray(&_Hpbballot.CallOpts, arg0)
}

// CandidateArray is a free data retrieval call binding the contract method 0x35a893a1.
//
// Solidity: function candidateArray( uint256) constant returns(candidateAddr address, balance uint256, name bytes32, facilityId bytes32, numberOfVotes uint256)
func (_Hpbballot *HpbballotCallerSession) CandidateArray(arg0 *big.Int) (struct {
	CandidateAddr common.Address
	Balance       *big.Int
	Name          [32]byte
	FacilityId    [32]byte
	NumberOfVotes *big.Int
}, error) {
	return _Hpbballot.Contract.CandidateArray(&_Hpbballot.CallOpts, arg0)
}

// CandidateIndexMap is a free data retrieval call binding the contract method 0x81f4bf85.
//
// Solidity: function candidateIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotCaller) CandidateIndexMap(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "candidateIndexMap", arg0)
	return *ret0, err
}

// CandidateIndexMap is a free data retrieval call binding the contract method 0x81f4bf85.
//
// Solidity: function candidateIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotSession) CandidateIndexMap(arg0 common.Address) (*big.Int, error) {
	return _Hpbballot.Contract.CandidateIndexMap(&_Hpbballot.CallOpts, arg0)
}

// CandidateIndexMap is a free data retrieval call binding the contract method 0x81f4bf85.
//
// Solidity: function candidateIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) CandidateIndexMap(arg0 common.Address) (*big.Int, error) {
	return _Hpbballot.Contract.CandidateIndexMap(&_Hpbballot.CallOpts, arg0)
}

// CandidateIndexMapAddrs is a free data retrieval call binding the contract method 0x13a3a7f3.
//
// Solidity: function candidateIndexMapAddrs( uint256) constant returns(address)
func (_Hpbballot *HpbballotCaller) CandidateIndexMapAddrs(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "candidateIndexMapAddrs", arg0)
	return *ret0, err
}

// CandidateIndexMapAddrs is a free data retrieval call binding the contract method 0x13a3a7f3.
//
// Solidity: function candidateIndexMapAddrs( uint256) constant returns(address)
func (_Hpbballot *HpbballotSession) CandidateIndexMapAddrs(arg0 *big.Int) (common.Address, error) {
	return _Hpbballot.Contract.CandidateIndexMapAddrs(&_Hpbballot.CallOpts, arg0)
}

// CandidateIndexMapAddrs is a free data retrieval call binding the contract method 0x13a3a7f3.
//
// Solidity: function candidateIndexMapAddrs( uint256) constant returns(address)
func (_Hpbballot *HpbballotCallerSession) CandidateIndexMapAddrs(arg0 *big.Int) (common.Address, error) {
	return _Hpbballot.Contract.CandidateIndexMapAddrs(&_Hpbballot.CallOpts, arg0)
}

// Capacity is a free data retrieval call binding the contract method 0x5cfc1a51.
//
// Solidity: function capacity() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) Capacity(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "capacity")
	return *ret0, err
}

// Capacity is a free data retrieval call binding the contract method 0x5cfc1a51.
//
// Solidity: function capacity() constant returns(uint256)
func (_Hpbballot *HpbballotSession) Capacity() (*big.Int, error) {
	return _Hpbballot.Contract.Capacity(&_Hpbballot.CallOpts)
}

// Capacity is a free data retrieval call binding the contract method 0x5cfc1a51.
//
// Solidity: function capacity() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) Capacity() (*big.Int, error) {
	return _Hpbballot.Contract.Capacity(&_Hpbballot.CallOpts)
}

// EndBlock is a free data retrieval call binding the contract method 0x083c6323.
//
// Solidity: function endBlock() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) EndBlock(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "endBlock")
	return *ret0, err
}

// EndBlock is a free data retrieval call binding the contract method 0x083c6323.
//
// Solidity: function endBlock() constant returns(uint256)
func (_Hpbballot *HpbballotSession) EndBlock() (*big.Int, error) {
	return _Hpbballot.Contract.EndBlock(&_Hpbballot.CallOpts)
}

// EndBlock is a free data retrieval call binding the contract method 0x083c6323.
//
// Solidity: function endBlock() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) EndBlock() (*big.Int, error) {
	return _Hpbballot.Contract.EndBlock(&_Hpbballot.CallOpts)
}

// FacilityIds is a free data retrieval call binding the contract method 0x342d8d7e.
//
// Solidity: function facilityIds( uint256) constant returns(bytes32)
func (_Hpbballot *HpbballotCaller) FacilityIds(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error) {
	var (
		ret0 = new([32]byte)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "facilityIds", arg0)
	return *ret0, err
}

// FacilityIds is a free data retrieval call binding the contract method 0x342d8d7e.
//
// Solidity: function facilityIds( uint256) constant returns(bytes32)
func (_Hpbballot *HpbballotSession) FacilityIds(arg0 *big.Int) ([32]byte, error) {
	return _Hpbballot.Contract.FacilityIds(&_Hpbballot.CallOpts, arg0)
}

// FacilityIds is a free data retrieval call binding the contract method 0x342d8d7e.
//
// Solidity: function facilityIds( uint256) constant returns(bytes32)
func (_Hpbballot *HpbballotCallerSession) FacilityIds(arg0 *big.Int) ([32]byte, error) {
	return _Hpbballot.Contract.FacilityIds(&_Hpbballot.CallOpts, arg0)
}

// HasReleaseAmount is a free data retrieval call binding the contract method 0x76023435.
//
// Solidity: function hasReleaseAmount() constant returns(bool)
func (_Hpbballot *HpbballotCaller) HasReleaseAmount(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "hasReleaseAmount")
	return *ret0, err
}

// HasReleaseAmount is a free data retrieval call binding the contract method 0x76023435.
//
// Solidity: function hasReleaseAmount() constant returns(bool)
func (_Hpbballot *HpbballotSession) HasReleaseAmount() (bool, error) {
	return _Hpbballot.Contract.HasReleaseAmount(&_Hpbballot.CallOpts)
}

// HasReleaseAmount is a free data retrieval call binding the contract method 0x76023435.
//
// Solidity: function hasReleaseAmount() constant returns(bool)
func (_Hpbballot *HpbballotCallerSession) HasReleaseAmount() (bool, error) {
	return _Hpbballot.Contract.HasReleaseAmount(&_Hpbballot.CallOpts)
}

// MinAmount is a free data retrieval call binding the contract method 0x9b2cb5d8.
//
// Solidity: function minAmount() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) MinAmount(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "minAmount")
	return *ret0, err
}

// MinAmount is a free data retrieval call binding the contract method 0x9b2cb5d8.
//
// Solidity: function minAmount() constant returns(uint256)
func (_Hpbballot *HpbballotSession) MinAmount() (*big.Int, error) {
	return _Hpbballot.Contract.MinAmount(&_Hpbballot.CallOpts)
}

// MinAmount is a free data retrieval call binding the contract method 0x9b2cb5d8.
//
// Solidity: function minAmount() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) MinAmount() (*big.Int, error) {
	return _Hpbballot.Contract.MinAmount(&_Hpbballot.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(bytes32)
func (_Hpbballot *HpbballotCaller) Name(opts *bind.CallOpts) ([32]byte, error) {
	var (
		ret0 = new([32]byte)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "name")
	return *ret0, err
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(bytes32)
func (_Hpbballot *HpbballotSession) Name() ([32]byte, error) {
	return _Hpbballot.Contract.Name(&_Hpbballot.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(bytes32)
func (_Hpbballot *HpbballotCallerSession) Name() ([32]byte, error) {
	return _Hpbballot.Contract.Name(&_Hpbballot.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Hpbballot *HpbballotCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Hpbballot *HpbballotSession) Owner() (common.Address, error) {
	return _Hpbballot.Contract.Owner(&_Hpbballot.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Hpbballot *HpbballotCallerSession) Owner() (common.Address, error) {
	return _Hpbballot.Contract.Owner(&_Hpbballot.CallOpts)
}

// StartBlock is a free data retrieval call binding the contract method 0x48cd4cb1.
//
// Solidity: function startBlock() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) StartBlock(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "startBlock")
	return *ret0, err
}

// StartBlock is a free data retrieval call binding the contract method 0x48cd4cb1.
//
// Solidity: function startBlock() constant returns(uint256)
func (_Hpbballot *HpbballotSession) StartBlock() (*big.Int, error) {
	return _Hpbballot.Contract.StartBlock(&_Hpbballot.CallOpts)
}

// StartBlock is a free data retrieval call binding the contract method 0x48cd4cb1.
//
// Solidity: function startBlock() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) StartBlock() (*big.Int, error) {
	return _Hpbballot.Contract.StartBlock(&_Hpbballot.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() constant returns(uint256)
func (_Hpbballot *HpbballotCaller) Version(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "version")
	return *ret0, err
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() constant returns(uint256)
func (_Hpbballot *HpbballotSession) Version() (*big.Int, error) {
	return _Hpbballot.Contract.Version(&_Hpbballot.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) Version() (*big.Int, error) {
	return _Hpbballot.Contract.Version(&_Hpbballot.CallOpts)
}

// VoterArray is a free data retrieval call binding the contract method 0xc279919f.
//
// Solidity: function voterArray( uint256) constant returns(voterAddr address)
func (_Hpbballot *HpbballotCaller) VoterArray(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "voterArray", arg0)
	return *ret0, err
}

// VoterArray is a free data retrieval call binding the contract method 0xc279919f.
//
// Solidity: function voterArray( uint256) constant returns(voterAddr address)
func (_Hpbballot *HpbballotSession) VoterArray(arg0 *big.Int) (common.Address, error) {
	return _Hpbballot.Contract.VoterArray(&_Hpbballot.CallOpts, arg0)
}

// VoterArray is a free data retrieval call binding the contract method 0xc279919f.
//
// Solidity: function voterArray( uint256) constant returns(voterAddr address)
func (_Hpbballot *HpbballotCallerSession) VoterArray(arg0 *big.Int) (common.Address, error) {
	return _Hpbballot.Contract.VoterArray(&_Hpbballot.CallOpts, arg0)
}

// VoterIndexMap is a free data retrieval call binding the contract method 0x903a0e6c.
//
// Solidity: function voterIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotCaller) VoterIndexMap(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "voterIndexMap", arg0)
	return *ret0, err
}

// VoterIndexMap is a free data retrieval call binding the contract method 0x903a0e6c.
//
// Solidity: function voterIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotSession) VoterIndexMap(arg0 common.Address) (*big.Int, error) {
	return _Hpbballot.Contract.VoterIndexMap(&_Hpbballot.CallOpts, arg0)
}

// VoterIndexMap is a free data retrieval call binding the contract method 0x903a0e6c.
//
// Solidity: function voterIndexMap( address) constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) VoterIndexMap(arg0 common.Address) (*big.Int, error) {
	return _Hpbballot.Contract.VoterIndexMap(&_Hpbballot.CallOpts, arg0)
}

// VotesNumArray is a free data retrieval call binding the contract method 0x725f66a6.
//
// Solidity: function votesNumArray( uint256) constant returns(uint256)
func (_Hpbballot *HpbballotCaller) VotesNumArray(opts *bind.CallOpts, arg0 *big.Int) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _Hpbballot.contract.Call(opts, out, "votesNumArray", arg0)
	return *ret0, err
}

// VotesNumArray is a free data retrieval call binding the contract method 0x725f66a6.
//
// Solidity: function votesNumArray( uint256) constant returns(uint256)
func (_Hpbballot *HpbballotSession) VotesNumArray(arg0 *big.Int) (*big.Int, error) {
	return _Hpbballot.Contract.VotesNumArray(&_Hpbballot.CallOpts, arg0)
}

// VotesNumArray is a free data retrieval call binding the contract method 0x725f66a6.
//
// Solidity: function votesNumArray( uint256) constant returns(uint256)
func (_Hpbballot *HpbballotCallerSession) VotesNumArray(arg0 *big.Int) (*big.Int, error) {
	return _Hpbballot.Contract.VotesNumArray(&_Hpbballot.CallOpts, arg0)
}

// AddCandidate is a paid mutator transaction binding the contract method 0xc767c18f.
//
// Solidity: function AddCandidate(_candidateAddr address, _facilityId bytes32, _name bytes32) returns()
func (_Hpbballot *HpbballotTransactor) AddCandidate(opts *bind.TransactOpts, _candidateAddr common.Address, _facilityId [32]byte, _name [32]byte) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "AddCandidate", _candidateAddr, _facilityId, _name)
}

// AddCandidate is a paid mutator transaction binding the contract method 0xc767c18f.
//
// Solidity: function AddCandidate(_candidateAddr address, _facilityId bytes32, _name bytes32) returns()
func (_Hpbballot *HpbballotSession) AddCandidate(_candidateAddr common.Address, _facilityId [32]byte, _name [32]byte) (*types.Transaction, error) {
	return _Hpbballot.Contract.AddCandidate(&_Hpbballot.TransactOpts, _candidateAddr, _facilityId, _name)
}

// AddCandidate is a paid mutator transaction binding the contract method 0xc767c18f.
//
// Solidity: function AddCandidate(_candidateAddr address, _facilityId bytes32, _name bytes32) returns()
func (_Hpbballot *HpbballotTransactorSession) AddCandidate(_candidateAddr common.Address, _facilityId [32]byte, _name [32]byte) (*types.Transaction, error) {
	return _Hpbballot.Contract.AddCandidate(&_Hpbballot.TransactOpts, _candidateAddr, _facilityId, _name)
}

// BeginVote is a paid mutator transaction binding the contract method 0x28bc5ee4.
//
// Solidity: function beginVote() returns()
func (_Hpbballot *HpbballotTransactor) BeginVote(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "beginVote")
}

// BeginVote is a paid mutator transaction binding the contract method 0x28bc5ee4.
//
// Solidity: function beginVote() returns()
func (_Hpbballot *HpbballotSession) BeginVote() (*types.Transaction, error) {
	return _Hpbballot.Contract.BeginVote(&_Hpbballot.TransactOpts)
}

// BeginVote is a paid mutator transaction binding the contract method 0x28bc5ee4.
//
// Solidity: function beginVote() returns()
func (_Hpbballot *HpbballotTransactorSession) BeginVote() (*types.Transaction, error) {
	return _Hpbballot.Contract.BeginVote(&_Hpbballot.TransactOpts)
}

// ChangeVotingBlocks is a paid mutator transaction binding the contract method 0x13a2f4a0.
//
// Solidity: function changeVotingBlocks(_name bytes32, _startBlock uint256, _endBlock uint256, _minAmount uint256, _capacity uint256, _version uint256) returns()
func (_Hpbballot *HpbballotTransactor) ChangeVotingBlocks(opts *bind.TransactOpts, _name [32]byte, _startBlock *big.Int, _endBlock *big.Int, _minAmount *big.Int, _capacity *big.Int, _version *big.Int) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "changeVotingBlocks", _name, _startBlock, _endBlock, _minAmount, _capacity, _version)
}

// ChangeVotingBlocks is a paid mutator transaction binding the contract method 0x13a2f4a0.
//
// Solidity: function changeVotingBlocks(_name bytes32, _startBlock uint256, _endBlock uint256, _minAmount uint256, _capacity uint256, _version uint256) returns()
func (_Hpbballot *HpbballotSession) ChangeVotingBlocks(_name [32]byte, _startBlock *big.Int, _endBlock *big.Int, _minAmount *big.Int, _capacity *big.Int, _version *big.Int) (*types.Transaction, error) {
	return _Hpbballot.Contract.ChangeVotingBlocks(&_Hpbballot.TransactOpts, _name, _startBlock, _endBlock, _minAmount, _capacity, _version)
}

// ChangeVotingBlocks is a paid mutator transaction binding the contract method 0x13a2f4a0.
//
// Solidity: function changeVotingBlocks(_name bytes32, _startBlock uint256, _endBlock uint256, _minAmount uint256, _capacity uint256, _version uint256) returns()
func (_Hpbballot *HpbballotTransactorSession) ChangeVotingBlocks(_name [32]byte, _startBlock *big.Int, _endBlock *big.Int, _minAmount *big.Int, _capacity *big.Int, _version *big.Int) (*types.Transaction, error) {
	return _Hpbballot.Contract.ChangeVotingBlocks(&_Hpbballot.TransactOpts, _name, _startBlock, _endBlock, _minAmount, _capacity, _version)
}

// DeleteCandidates is a paid mutator transaction binding the contract method 0xabe6c54d.
//
// Solidity: function deleteCandidates(_candidateAddr address) returns()
func (_Hpbballot *HpbballotTransactor) DeleteCandidates(opts *bind.TransactOpts, _candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "deleteCandidates", _candidateAddr)
}

// DeleteCandidates is a paid mutator transaction binding the contract method 0xabe6c54d.
//
// Solidity: function deleteCandidates(_candidateAddr address) returns()
func (_Hpbballot *HpbballotSession) DeleteCandidates(_candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.DeleteCandidates(&_Hpbballot.TransactOpts, _candidateAddr)
}

// DeleteCandidates is a paid mutator transaction binding the contract method 0xabe6c54d.
//
// Solidity: function deleteCandidates(_candidateAddr address) returns()
func (_Hpbballot *HpbballotTransactorSession) DeleteCandidates(_candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.DeleteCandidates(&_Hpbballot.TransactOpts, _candidateAddr)
}

// EndVote is a paid mutator transaction binding the contract method 0xb9223946.
//
// Solidity: function endVote() returns()
func (_Hpbballot *HpbballotTransactor) EndVote(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "endVote")
}

// EndVote is a paid mutator transaction binding the contract method 0xb9223946.
//
// Solidity: function endVote() returns()
func (_Hpbballot *HpbballotSession) EndVote() (*types.Transaction, error) {
	return _Hpbballot.Contract.EndVote(&_Hpbballot.TransactOpts)
}

// EndVote is a paid mutator transaction binding the contract method 0xb9223946.
//
// Solidity: function endVote() returns()
func (_Hpbballot *HpbballotTransactorSession) EndVote() (*types.Transaction, error) {
	return _Hpbballot.Contract.EndVote(&_Hpbballot.TransactOpts)
}

// FechVoteInfoForCandidate is a paid mutator transaction binding the contract method 0x9eace9bd.
//
// Solidity: function fechVoteInfoForCandidate() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotTransactor) FechVoteInfoForCandidate(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "fechVoteInfoForCandidate")
}

// FechVoteInfoForCandidate is a paid mutator transaction binding the contract method 0x9eace9bd.
//
// Solidity: function fechVoteInfoForCandidate() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotSession) FechVoteInfoForCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForCandidate(&_Hpbballot.TransactOpts)
}

// FechVoteInfoForCandidate is a paid mutator transaction binding the contract method 0x9eace9bd.
//
// Solidity: function fechVoteInfoForCandidate() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotTransactorSession) FechVoteInfoForCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForCandidate(&_Hpbballot.TransactOpts)
}

// FechVoteInfoForCandidateByVoterAddr is a paid mutator transaction binding the contract method 0xa1a1d72c.
//
// Solidity: function fechVoteInfoForCandidateByVoterAddr(voterAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotTransactor) FechVoteInfoForCandidateByVoterAddr(opts *bind.TransactOpts, voterAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "fechVoteInfoForCandidateByVoterAddr", voterAddr)
}

// FechVoteInfoForCandidateByVoterAddr is a paid mutator transaction binding the contract method 0xa1a1d72c.
//
// Solidity: function fechVoteInfoForCandidateByVoterAddr(voterAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotSession) FechVoteInfoForCandidateByVoterAddr(voterAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForCandidateByVoterAddr(&_Hpbballot.TransactOpts, voterAddr)
}

// FechVoteInfoForCandidateByVoterAddr is a paid mutator transaction binding the contract method 0xa1a1d72c.
//
// Solidity: function fechVoteInfoForCandidateByVoterAddr(voterAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotTransactorSession) FechVoteInfoForCandidateByVoterAddr(voterAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForCandidateByVoterAddr(&_Hpbballot.TransactOpts, voterAddr)
}

// FechVoteInfoForVoter is a paid mutator transaction binding the contract method 0xe47d914a.
//
// Solidity: function fechVoteInfoForVoter() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotTransactor) FechVoteInfoForVoter(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "fechVoteInfoForVoter")
}

// FechVoteInfoForVoter is a paid mutator transaction binding the contract method 0xe47d914a.
//
// Solidity: function fechVoteInfoForVoter() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotSession) FechVoteInfoForVoter() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForVoter(&_Hpbballot.TransactOpts)
}

// FechVoteInfoForVoter is a paid mutator transaction binding the contract method 0xe47d914a.
//
// Solidity: function fechVoteInfoForVoter() returns(addrs address[], nums uint256[])
func (_Hpbballot *HpbballotTransactorSession) FechVoteInfoForVoter() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForVoter(&_Hpbballot.TransactOpts)
}

// FechVoteInfoForVoterByCandidateAddr is a paid mutator transaction binding the contract method 0x9ab744e6.
//
// Solidity: function fechVoteInfoForVoterByCandidateAddr(candidateAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotTransactor) FechVoteInfoForVoterByCandidateAddr(opts *bind.TransactOpts, candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "fechVoteInfoForVoterByCandidateAddr", candidateAddr)
}

// FechVoteInfoForVoterByCandidateAddr is a paid mutator transaction binding the contract method 0x9ab744e6.
//
// Solidity: function fechVoteInfoForVoterByCandidateAddr(candidateAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotSession) FechVoteInfoForVoterByCandidateAddr(candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForVoterByCandidateAddr(&_Hpbballot.TransactOpts, candidateAddr)
}

// FechVoteInfoForVoterByCandidateAddr is a paid mutator transaction binding the contract method 0x9ab744e6.
//
// Solidity: function fechVoteInfoForVoterByCandidateAddr(candidateAddr address) returns(nums uint256)
func (_Hpbballot *HpbballotTransactorSession) FechVoteInfoForVoterByCandidateAddr(candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteInfoForVoterByCandidateAddr(&_Hpbballot.TransactOpts, candidateAddr)
}

// FechVoteResultForCandidate is a paid mutator transaction binding the contract method 0xa4adc431.
//
// Solidity: function fechVoteResultForCandidate() returns(num uint256)
func (_Hpbballot *HpbballotTransactor) FechVoteResultForCandidate(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "fechVoteResultForCandidate")
}

// FechVoteResultForCandidate is a paid mutator transaction binding the contract method 0xa4adc431.
//
// Solidity: function fechVoteResultForCandidate() returns(num uint256)
func (_Hpbballot *HpbballotSession) FechVoteResultForCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteResultForCandidate(&_Hpbballot.TransactOpts)
}

// FechVoteResultForCandidate is a paid mutator transaction binding the contract method 0xa4adc431.
//
// Solidity: function fechVoteResultForCandidate() returns(num uint256)
func (_Hpbballot *HpbballotTransactorSession) FechVoteResultForCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.FechVoteResultForCandidate(&_Hpbballot.TransactOpts)
}

// PayDepositByCandidate is a paid mutator transaction binding the contract method 0x927731c8.
//
// Solidity: function payDepositByCandidate() returns()
func (_Hpbballot *HpbballotTransactor) PayDepositByCandidate(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "payDepositByCandidate")
}

// PayDepositByCandidate is a paid mutator transaction binding the contract method 0x927731c8.
//
// Solidity: function payDepositByCandidate() returns()
func (_Hpbballot *HpbballotSession) PayDepositByCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.PayDepositByCandidate(&_Hpbballot.TransactOpts)
}

// PayDepositByCandidate is a paid mutator transaction binding the contract method 0x927731c8.
//
// Solidity: function payDepositByCandidate() returns()
func (_Hpbballot *HpbballotTransactorSession) PayDepositByCandidate() (*types.Transaction, error) {
	return _Hpbballot.Contract.PayDepositByCandidate(&_Hpbballot.TransactOpts)
}

// ReleaseAmount is a paid mutator transaction binding the contract method 0xc062dc5f.
//
// Solidity: function releaseAmount() returns()
func (_Hpbballot *HpbballotTransactor) ReleaseAmount(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "releaseAmount")
}

// ReleaseAmount is a paid mutator transaction binding the contract method 0xc062dc5f.
//
// Solidity: function releaseAmount() returns()
func (_Hpbballot *HpbballotSession) ReleaseAmount() (*types.Transaction, error) {
	return _Hpbballot.Contract.ReleaseAmount(&_Hpbballot.TransactOpts)
}

// ReleaseAmount is a paid mutator transaction binding the contract method 0xc062dc5f.
//
// Solidity: function releaseAmount() returns()
func (_Hpbballot *HpbballotTransactorSession) ReleaseAmount() (*types.Transaction, error) {
	return _Hpbballot.Contract.ReleaseAmount(&_Hpbballot.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Hpbballot *HpbballotTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Hpbballot *HpbballotSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.TransferOwnership(&_Hpbballot.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Hpbballot *HpbballotTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.TransferOwnership(&_Hpbballot.TransactOpts, newOwner)
}

// VoteBySendHpb is a paid mutator transaction binding the contract method 0x9dc5b6df.
//
// Solidity: function voteBySendHpb(candidateAddr address) returns(serialNumber uint256)
func (_Hpbballot *HpbballotTransactor) VoteBySendHpb(opts *bind.TransactOpts, candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "voteBySendHpb", candidateAddr)
}

// VoteBySendHpb is a paid mutator transaction binding the contract method 0x9dc5b6df.
//
// Solidity: function voteBySendHpb(candidateAddr address) returns(serialNumber uint256)
func (_Hpbballot *HpbballotSession) VoteBySendHpb(candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.VoteBySendHpb(&_Hpbballot.TransactOpts, candidateAddr)
}

// VoteBySendHpb is a paid mutator transaction binding the contract method 0x9dc5b6df.
//
// Solidity: function voteBySendHpb(candidateAddr address) returns(serialNumber uint256)
func (_Hpbballot *HpbballotTransactorSession) VoteBySendHpb(candidateAddr common.Address) (*types.Transaction, error) {
	return _Hpbballot.Contract.VoteBySendHpb(&_Hpbballot.TransactOpts, candidateAddr)
}

// VoteResult is a paid mutator transaction binding the contract method 0x003259ea.
//
// Solidity: function voteResult() returns(addr address[], _facilityIds bytes32[], nums uint256[])
func (_Hpbballot *HpbballotTransactor) VoteResult(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Hpbballot.contract.Transact(opts, "voteResult")
}

// VoteResult is a paid mutator transaction binding the contract method 0x003259ea.
//
// Solidity: function voteResult() returns(addr address[], _facilityIds bytes32[], nums uint256[])
func (_Hpbballot *HpbballotSession) VoteResult() (*types.Transaction, error) {
	return _Hpbballot.Contract.VoteResult(&_Hpbballot.TransactOpts)
}

// VoteResult is a paid mutator transaction binding the contract method 0x003259ea.
//
// Solidity: function voteResult() returns(addr address[], _facilityIds bytes32[], nums uint256[])
func (_Hpbballot *HpbballotTransactorSession) VoteResult() (*types.Transaction, error) {
	return _Hpbballot.Contract.VoteResult(&_Hpbballot.TransactOpts)
}

// SafeMathABI is the input ABI used to generate the binding from.
const SafeMathABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"MAX_UINT256\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

// SafeMathBin is the compiled bytecode used for deploying new contracts.
const SafeMathBin = `0x6080604052348015600f57600080fd5b5060998061001e6000396000f300608060405260043610603e5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166333a581d281146043575b600080fd5b348015604e57600080fd5b5060556067565b60408051918252519081900360200190f35b600019815600a165627a7a72305820da2ac2fdea0d83aa8ec1c8e5dd4e92cd42aafe84b7c7b3271fad5b0c6a4810360029`

// DeploySafeMath deploys a new Ethereum contract, binding an instance of SafeMath to it.
func DeploySafeMath(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *SafeMath, error) {
	parsed, err := abi.JSON(strings.NewReader(SafeMathABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(SafeMathBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SafeMath{SafeMathCaller: SafeMathCaller{contract: contract}, SafeMathTransactor: SafeMathTransactor{contract: contract}}, nil
}

// SafeMath is an auto generated Go binding around an Ethereum contract.
type SafeMath struct {
	SafeMathCaller     // Read-only binding to the contract
	SafeMathTransactor // Write-only binding to the contract
}

// SafeMathCaller is an auto generated read-only Go binding around an Ethereum contract.
type SafeMathCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SafeMathTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SafeMathTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SafeMathSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SafeMathSession struct {
	Contract     *SafeMath         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SafeMathCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SafeMathCallerSession struct {
	Contract *SafeMathCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// SafeMathTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SafeMathTransactorSession struct {
	Contract     *SafeMathTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// SafeMathRaw is an auto generated low-level Go binding around an Ethereum contract.
type SafeMathRaw struct {
	Contract *SafeMath // Generic contract binding to access the raw methods on
}

// SafeMathCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SafeMathCallerRaw struct {
	Contract *SafeMathCaller // Generic read-only contract binding to access the raw methods on
}

// SafeMathTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SafeMathTransactorRaw struct {
	Contract *SafeMathTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSafeMath creates a new instance of SafeMath, bound to a specific deployed contract.
func NewSafeMath(address common.Address, backend bind.ContractBackend) (*SafeMath, error) {
	contract, err := bindSafeMath(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SafeMath{SafeMathCaller: SafeMathCaller{contract: contract}, SafeMathTransactor: SafeMathTransactor{contract: contract}}, nil
}

// NewSafeMathCaller creates a new read-only instance of SafeMath, bound to a specific deployed contract.
func NewSafeMathCaller(address common.Address, caller bind.ContractCaller) (*SafeMathCaller, error) {
	contract, err := bindSafeMath(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &SafeMathCaller{contract: contract}, nil
}

// NewSafeMathTransactor creates a new write-only instance of SafeMath, bound to a specific deployed contract.
func NewSafeMathTransactor(address common.Address, transactor bind.ContractTransactor) (*SafeMathTransactor, error) {
	contract, err := bindSafeMath(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &SafeMathTransactor{contract: contract}, nil
}

// bindSafeMath binds a generic wrapper to an already deployed contract.
func bindSafeMath(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SafeMathABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SafeMath *SafeMathRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _SafeMath.Contract.SafeMathCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SafeMath *SafeMathRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SafeMath.Contract.SafeMathTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SafeMath *SafeMathRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SafeMath.Contract.SafeMathTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SafeMath *SafeMathCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _SafeMath.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SafeMath *SafeMathTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SafeMath.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SafeMath *SafeMathTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SafeMath.Contract.contract.Transact(opts, method, params...)
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_SafeMath *SafeMathCaller) MAX_UINT256(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _SafeMath.contract.Call(opts, out, "MAX_UINT256")
	return *ret0, err
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_SafeMath *SafeMathSession) MAX_UINT256() (*big.Int, error) {
	return _SafeMath.Contract.MAX_UINT256(&_SafeMath.CallOpts)
}

// MAX_UINT256 is a free data retrieval call binding the contract method 0x33a581d2.
//
// Solidity: function MAX_UINT256() constant returns(uint256)
func (_SafeMath *SafeMathCallerSession) MAX_UINT256() (*big.Int, error) {
	return _SafeMath.Contract.MAX_UINT256(&_SafeMath.CallOpts)
}

// OwnedABI is the input ABI used to generate the binding from.
const OwnedABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// OwnedBin is the compiled bytecode used for deploying new contracts.
const OwnedBin = `0x608060405234801561001057600080fd5b5060008054600160a060020a03191633179055610166806100326000396000f30060806040526004361061004b5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416638da5cb5b8114610050578063f2fde38b1461008e575b600080fd5b34801561005c57600080fd5b506100656100be565b6040805173ffffffffffffffffffffffffffffffffffffffff9092168252519081900360200190f35b34801561009a57600080fd5b506100bc73ffffffffffffffffffffffffffffffffffffffff600435166100da565b005b60005473ffffffffffffffffffffffffffffffffffffffff1681565b60005473ffffffffffffffffffffffffffffffffffffffff1633146100fe57600080fd5b6000805473ffffffffffffffffffffffffffffffffffffffff191673ffffffffffffffffffffffffffffffffffffffff929092169190911790555600a165627a7a72305820cded8ea4fdecaef5fdfe3c7c45f1690261777108e62be546965b6489a2636b650029`

// DeployOwned deploys a new Ethereum contract, binding an instance of Owned to it.
func DeployOwned(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Owned, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnedABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(OwnedBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Owned{OwnedCaller: OwnedCaller{contract: contract}, OwnedTransactor: OwnedTransactor{contract: contract}}, nil
}

// Owned is an auto generated Go binding around an Ethereum contract.
type Owned struct {
	OwnedCaller     // Read-only binding to the contract
	OwnedTransactor // Write-only binding to the contract
}

// OwnedCaller is an auto generated read-only Go binding around an Ethereum contract.
type OwnedCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnedTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OwnedTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnedSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OwnedSession struct {
	Contract     *Owned            // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// OwnedCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OwnedCallerSession struct {
	Contract *OwnedCaller  // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// OwnedTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OwnedTransactorSession struct {
	Contract     *OwnedTransactor  // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// OwnedRaw is an auto generated low-level Go binding around an Ethereum contract.
type OwnedRaw struct {
	Contract *Owned // Generic contract binding to access the raw methods on
}

// OwnedCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OwnedCallerRaw struct {
	Contract *OwnedCaller // Generic read-only contract binding to access the raw methods on
}

// OwnedTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OwnedTransactorRaw struct {
	Contract *OwnedTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOwned creates a new instance of Owned, bound to a specific deployed contract.
func NewOwned(address common.Address, backend bind.ContractBackend) (*Owned, error) {
	contract, err := bindOwned(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Owned{OwnedCaller: OwnedCaller{contract: contract}, OwnedTransactor: OwnedTransactor{contract: contract}}, nil
}

// NewOwnedCaller creates a new read-only instance of Owned, bound to a specific deployed contract.
func NewOwnedCaller(address common.Address, caller bind.ContractCaller) (*OwnedCaller, error) {
	contract, err := bindOwned(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &OwnedCaller{contract: contract}, nil
}

// NewOwnedTransactor creates a new write-only instance of Owned, bound to a specific deployed contract.
func NewOwnedTransactor(address common.Address, transactor bind.ContractTransactor) (*OwnedTransactor, error) {
	contract, err := bindOwned(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &OwnedTransactor{contract: contract}, nil
}

// bindOwned binds a generic wrapper to an already deployed contract.
func bindOwned(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnedABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Owned *OwnedRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Owned.Contract.OwnedCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Owned *OwnedRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Owned.Contract.OwnedTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Owned *OwnedRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Owned.Contract.OwnedTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Owned *OwnedCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Owned.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Owned *OwnedTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Owned.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Owned *OwnedTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Owned.Contract.contract.Transact(opts, method, params...)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Owned *OwnedCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Owned.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Owned *OwnedSession) Owner() (common.Address, error) {
	return _Owned.Contract.Owner(&_Owned.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_Owned *OwnedCallerSession) Owner() (common.Address, error) {
	return _Owned.Contract.Owner(&_Owned.CallOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Owned *OwnedTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Owned.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Owned *OwnedSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Owned.Contract.TransferOwnership(&_Owned.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(newOwner address) returns()
func (_Owned *OwnedTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Owned.Contract.TransferOwnership(&_Owned.TransactOpts, newOwner)
}
