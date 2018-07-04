pragma solidity ^0.4.16;

/* https://github.com/LykkeCity/EthereumApiDotNetCore/blob/master/src/ContractBuilder/contracts/token/SafeMath.sol */
contract SafeMath {
    uint256 constant public MAX_UINT256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    function safeAdd(uint256 x, uint256 y) pure internal returns (uint256 z){
        if (x > MAX_UINT256 - y) {
            revert();
        }
        return x + y;
    }

    function safeSub(uint256 x, uint256 y) pure internal returns (uint256 z){
        if (x < y){
            revert();
        }
        return x - y;
    }

    function safeMul(uint256 x, uint256 y) pure internal returns (uint256 z){
        if (y == 0){
            return 0;
        }
        if (x > MAX_UINT256 / y) {
            revert();
        }
        return x * y;
    }

}
/**
 * 只有HPB基金会账户（管理员）可以调用
 */
contract owned {
    address public owner;
    constructor()public{
        owner = msg.sender;
    }

    modifier onlyOwner{
        require(msg.sender == owner);
        // Do not forget the "_;"! It will be replaced by the actual function
        // body when the modifier is used.
        _;
    }

    function transferOwnership(address newOwner) onlyOwner  public{
        owner = newOwner;
    }
}


contract Hpbballot is owned,SafeMath {
    // 票池名称
    // pool name
    bytes32 public name = "HPBBallot";
    // 开始投票的区块号
    // `startBlock` specifies from which block our vote starts.
    uint public startBlock = 0;
    // 结束投票的区块号
    // `endBlock` specifies from which block our vote ends.
    uint public endBlock = 0;
    // 当前票池的版本号
    // currrent pool version
    uint public version = 1;
    //最终获选总数
    uint public capacity = 0;

    // 候选者的结构体
    struct Candidate{
        // 候选人地址
        address candidateAddr;
        // 保证金金额
        uint balance;
        // 候选人名称
        bytes32 name;
        // 候选者机器id(编号或者节点)
        bytes32 facilityId;
        // 得票数
        uint numberOfVotes;
        // 已经投票了投票人账户地址-》投票数
        mapping (address => uint) voterMap;
        //用于遍历用途
        address[] voterMapAddrs;
        //便于候选者查询，并减少gas消耗
        uint[] voterMapNumArray;
    }
    // 投票结构体
    struct Voter{
        // 投票人地址
        address voterAddr;
        // 已经投票了候选者账户地址-》投票数
        mapping (address => uint) candidateMap;
        //用于遍历用途
        address[] candidateMapAddrs;
        //便于投票者查询，并减少gas消耗
        uint[] candidateMapArray;
    }
    //候选者的地址与候选者排位(按加入时间排序)序号对应关系
    mapping (address => uint) public candidateIndexMap;
    //便于返回候选结果，并减少gas消耗
    address[] public candidateIndexMapAddrs;
    //当选票数
    uint[] public votesNumArray;
    //便于返回候选结果，并减少gas消耗
    bytes32[] public facilityIds;
    // 候选者的数组
    // An array of candidates
    Candidate[] public candidateArray;
    // 候选者保证金最少金额，比如1000个HPB(10 ** 20)
    uint public minAmount = 10 ** 20;
    //是否释放保证金
    bool public hasReleaseAmount=false;
    // 投票者的地址与投票者序号对应关系，便于查询和减少gas消耗
    mapping (address => uint) public voterIndexMap;
    // 投票者的数组
    // An array of voters
    Voter[] public voterArray;

    // 增加候选者 传入候选者id(序号)，候选者机器id，候选者地址，候选者名称
    event CandidateAdded(uint serialNumber, bytes32 facilityId,address candidateAddr,bytes32 name);

    // 投票，传入投票人地址，候选者序号，候选者机器id，候选者地址
    event Voted(address VoteAddr,uint serialNumber, bytes32 facilityId,address candidateAddr);

    // 改变投票区间值,改变保证金最少金额,改变投票版本号
    event ChangeOfBlocks(bytes32 name,uint startBlock, uint endBlock,uint minAmount,uint capacity,uint version);

    // 记录发送HPB的发送者地址和发送的金额
    event receivedEther(address sender, uint amount);

	//接受HPB转账
    function () payable  public{
       emit receivedEther(msg.sender, msg.value);
    }

    /**
     * Constructor function
     * 构造函数
     */
    constructor( // 票池名称
    	// pool name
    	bytes32 _name,

        //开始投票的区块号
    	// `startBlock` specifies from which block our vote starts.
        uint _startBlock,

        //结束投票的区块号
        // `endBlock` specifies from which block our vote ends.
        uint _endBlock,

        //保证金最少金额
        uint _minAmount,

        //当选个数
        uint _capacity,

        //当前票池的版本号
        //currrent pool version
        uint _version
     ) payable public{
	        name=_name;
	        startBlock= _startBlock;
	        endBlock= _endBlock;
	        minAmount=_minAmount;
	        capacity=_capacity;
	        version=_version;
	        emit ChangeOfBlocks(_name,_startBlock,_endBlock,_minAmount,_capacity,_version);
     }


    function changeVotingBlocks(
        bytes32 _name,
        uint _startBlock,
        uint _endBlock,
        uint _minAmount,
        uint _capacity,
        uint _version
    ) onlyOwner public{
        name = _name;
        startBlock = _startBlock;
        endBlock = _endBlock;
        minAmount = _minAmount;
        capacity = _capacity;
        version = _version;
        emit ChangeOfBlocks(_name,_startBlock, _endBlock,_minAmount,_capacity,_version);
    }
    //启动投票开始
    function beginVote() onlyOwner public{
        startBlock = block.number;
    }
   //结束投票
    function endVote() onlyOwner public{
        endBlock = block.number;
    }
   // 只有投票开始后执行
    modifier onlyVoteAfterStart{
        require(block.number>= startBlock);
        _;
    }
    // 只有投票进行中执行
    modifier onlyVoteInProgress{
        require(block.number>= startBlock);
        require(block.number<= endBlock);
        _;
    }

    // 只有投票结束前执行
    modifier onlyVoteBeforeEnd{
        require(block.number<= endBlock);
        _;
    }

    // 只有投票结束后执行
    modifier onlyVoteAfterEnd{
        require(block.number> endBlock);
        _;
    }

    /**
     * Add Candidate 增加候选者
     *
     * @param _candidateAddr 候选者账户地址，用于质押和返回质押的HPB
     * @param _facilityId 候选者机器设备号或者节点ID
     * @param _name 候选者名称
     *
     */
    function AddCandidate(
        address _candidateAddr,
        bytes32 _facilityId,
        bytes32 _name
    ) onlyOwner onlyVoteBeforeEnd public{
        uint index = candidateIndexMap[_candidateAddr];
        // 判断候选人是否已经存在
        if (index == 0) { // 如果没有，就添加
            index = candidateArray.length;
            candidateIndexMap[_candidateAddr]=index;
            candidateArray.length =safeAdd(index,1);
            candidateIndexMapAddrs.length =safeAdd(index,1);
            votesNumArray.length =safeAdd(index,1);
            facilityIds.length =safeAdd(index,1);
        }
        address[] memory _voterMapAddrs = new address[](1);
        uint[] memory _voterMapNumArray = new uint[](1);
        // 无论如何，都覆盖原有的数组对象(比如候选者修改了设备id)
        candidateArray[index]=Candidate({
	        candidateAddr:_candidateAddr,
	        balance:0,
	        name: _name,
	        facilityId: _facilityId,
	        numberOfVotes: 0,
	        voterMapAddrs:_voterMapAddrs,
	        voterMapNumArray:_voterMapNumArray
        });
        candidateIndexMapAddrs[index]=_candidateAddr;
        votesNumArray[index]=0;
        facilityIds[index]=_facilityId;
        emit CandidateAdded(index,_facilityId,_candidateAddr,_name);
    }

    /**
     * Delete Candidate 删除候选者
     *
     * @param _candidateAddr 候选者账户地址
     *
     */
    function deleteCandidates(
        address _candidateAddr
    ) onlyOwner onlyVoteBeforeEnd public{
        require(candidateIndexMap[_candidateAddr] != 0);
        for (uint i = candidateIndexMap[_candidateAddr];i<candidateArray.length-1;i++){
            candidateArray[i] = candidateArray[i+1];
            votesNumArray[i] = votesNumArray[i+1];
            facilityIds[i] = facilityIds[i+1];
        }
        delete candidateArray[candidateArray.length-1];
        delete votesNumArray[votesNumArray.length-1];
        delete facilityIds[facilityIds.length-1];
        candidateArray.length--;
        votesNumArray.length--;
        facilityIds.length--;
    }
    /**
     * 缴纳保证金
     */
    function payDepositByCandidate() onlyVoteBeforeEnd payable public{
        uint index = candidateIndexMap[msg.sender];
        // 判断候选人是否已经存在
        require(index>0);
        Candidate memory candidate=candidateArray[index];
        candidate.balance=safeAdd(candidate.balance,msg.value);
    }
	/**
     * 获取投票人的投票记录
     */
    function fechVoteInfoForVoter() onlyVoteAfterStart public returns (address[] addrs,uint[] nums){

        uint index = voterIndexMap[msg.sender];
        require(index> 0);
        //如果投过票，就获取投票人对应的投票候选者(多个，以map形式存放)
        mapping (address => uint) _candidateMap=voterArray[index].candidateMap;
        address[] memory _candidateMapAddrs=voterArray[index].candidateMapAddrs;
        uint[] memory numsa=new uint[](_candidateMapAddrs.length);
        for (uint i = 0;i<_candidateMapAddrs.length-1;i++){
            numsa[i]=_candidateMap[_candidateMapAddrs[i]];
        }
        return (_candidateMapAddrs,numsa);
    }
    /**
     * 获取投票人对某个候选人的投票记录
     */
    function fechVoteInfoForVoterByCandidateAddr(
        address candidateAddr
    ) onlyVoteAfterStart public returns (
        uint nums
    ){
        uint index = voterIndexMap[msg.sender];
        if (index == 0) { // 如果从没投过票
            return 0;
        } else { // 如果投过票，就获取投票人对应的投票候选者(多个，以map形式存放)
            mapping (address => uint) _candidateMap=voterArray[index].candidateMap;
            return _candidateMap[candidateAddr];
        }
    }
	/**
     * 获取候选人的竞选情况
     */
    function fechVoteInfoForCandidate(
    ) onlyVoteAfterStart public returns (
        address[] addrs,uint[] nums
    ){
        uint index = candidateIndexMap[msg.sender];
        // 如果候选人存在
        require(index>0);
        mapping (address => uint) _voterMap=candidateArray[index].voterMap;
        address[] memory _voterMapAddrs=candidateArray[index].voterMapAddrs;
        uint[] memory numsa=new uint[](_voterMapAddrs.length);
        for (uint i = 0;i<_voterMapAddrs.length-1;i++){
             numsa[i]=_voterMap[_voterMapAddrs[i]];
        }
        return (_voterMapAddrs,numsa);
    }
    /**
     * 获取候选人被某个投票人的投票记录
     */
    function fechVoteInfoForCandidateByVoterAddr(
        address voterAddr
    ) onlyVoteAfterStart public returns (
        uint nums
    ){
        uint index = candidateIndexMap[msg.sender];
        if (index == 0) { // 如果候选人不存在
            return 0;
        } else {
            mapping (address => uint) _voterMap=candidateArray[index].voterMap;
            return _voterMap[voterAddr];
        }
    }
    /**
     * 获取候选人的竞选结果
     */
    function fechVoteResultForCandidate(
    ) onlyVoteAfterStart public returns (
        uint num
    ){
        uint index = candidateIndexMap[msg.sender];
        if (index == 0) { // 如果候选人不存在
            return 0;
        } else {
            return candidateArray[index].numberOfVotes;
        }
    }

    /**
     * vote for a candidate
     * 进行投票 返回候选人序号
     * @param candidateAddr 候选人HPB账户地址
     */
    function voteBySendHpb(
        address candidateAddr
    ) onlyVoteInProgress payable public returns (
        uint serialNumber
    ){
        // 获取投票人的账户地址
        address r = msg.sender;
        // 获取投票人的投票数量(以发送HPB的额度作为票数)
        uint v = msg.value;
        return vote(candidateAddr, r,v);
    }
    Candidate vote_candidate;

    function vote(
        address candidateAddr,
        address r,
        uint v
    ) onlyVoteInProgress internal returns (
        uint serialNumber
    ){
        // 必须给候选人投票
        require(candidateIndexMap[candidateAddr]!=0);
        // Get the candidate 获取候选人
        vote_candidate= candidateArray[candidateIndexMap[candidateAddr]];
        // 必须缴纳足够的保证金
        require(vote_candidate.balance>=minAmount);
        // 添加候选者得票数量
        vote_candidate.numberOfVotes=safeAdd(vote_candidate.numberOfVotes,v);
        votesNumArray[candidateIndexMap[candidateAddr]]=vote_candidate.numberOfVotes;
        // 获取候选人中的投票人信息，并重新记录投票数
        if(vote_candidate.voterMap[r]==0)	{
            vote_candidate.voterMap[r]=v;
        } else {
            vote_candidate.voterMap[r]=safeAdd(vote_candidate.voterMap[r],v);
        }
        // 记录投票人对候选人投票的记录
        uint index = voterIndexMap[r];
        if (index == 0) { // 如果从没投过票，就添加投票人
            index =voterArray.length;
            voterIndexMap[r] = index;
            voterArray.length = safeAdd(index,1);
        }
         //用于遍历用途
        address[] memory _candidateMapAddrs=new address[](0);
        //便于投票者查询，并减少gas消耗
        uint[] memory _candidateMapArray=new uint[](0);
        voterArray[index]=Voter({
		        voterAddr:r,
		        candidateMapAddrs:_candidateMapAddrs,
		        candidateMapArray:_candidateMapArray
		});
		mapping  (address  => uint) vote_candidateMap=voterArray[index].candidateMap;
        vote_candidateMap[candidateAddr]=vote_candidate.voterMap[r];
		emit Voted(r,serialNumber, vote_candidate.facilityId,candidateAddr);
        return candidateIndexMap[candidateAddr];
    }
    /**
     * 释放保证金
     */
    function releaseAmount(
    ) onlyOwner onlyVoteAfterEnd public{
        if(!hasReleaseAmount){
            hasReleaseAmount=true;
            for (uint i = 0;i<candidateArray.length-1;i++){
                if(candidateArray[i].balance>0){
                    candidateArray[i].candidateAddr.transfer(candidateArray[i].balance);
                    candidateArray[i].balance=0;
                }
            }
        }
    }
    uint[] u=new uint[](0);
    address[] _addr=new address[](0);
    bytes32[] _facilityId=new bytes32[](0);
    uint[] _nums=new uint[](0);
    /**
     * 得到最终投票结果
      */
    function voteResult(
    ) onlyVoteAfterEnd public returns(
        address[] addr,
        bytes32[] _facilityIds,
        uint[] nums
    ){
         _addr.push(candidateIndexMapAddrs[0]);
         _facilityId.push(_facilityIds[0]);

         _nums.push(votesNumArray[0]);
         uint min=votesNumArray[0];
         uint minIndex=0;

         for (uint i = 1;i<candidateArray.length-1;i++){
             if(!hasReleaseAmount){//自动释放保证金
	             if(i==1){
	                 if(candidateArray[0].balance>0){
	                 	candidateArray[0].candidateAddr.transfer(candidateArray[0].balance);
	                 	candidateArray[0].balance=0;
	                 }
	             }
	             if(candidateArray[i].balance>0){
	                 candidateArray[i].candidateAddr.transfer(candidateArray[i].balance);
	                 candidateArray[i].balance=0;
	             }
             }
             if(i<=capacity){
                 u.push(i);
                 _addr.push(candidateIndexMapAddrs[i]);
                 _facilityId.push(_facilityIds[i]);
                 _nums.push(votesNumArray[i]);
                 if(votesNumArray[i]<min){
                     min=votesNumArray[i];
                     minIndex=i;
                 }
             }else{
               if(votesNumArray[i]>min){
                   u[minIndex]=i;
                   _addr[minIndex]=candidateIndexMapAddrs[i];
                   _facilityId[minIndex]=_facilityIds[i];
                   _nums[minIndex]=votesNumArray[i];
                   //重新获取最小得票数，并设置最小投票数的位置
                   for(uint n=0;n<u.length-1;n++){
                       if(votesNumArray[u[n]]<min){
		                     min=votesNumArray[u[n]];
		                     minIndex=n;
		                }
                   }
               }
             }
        }
        hasReleaseAmount=true;
        return (_addr,_facilityId,_nums);
    }

}