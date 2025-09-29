// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ChainPay - Secure Version
 * @dev A decentralized payment system with enhanced security features
 * @notice All critical vulnerabilities from audit have been addressed
 */
contract ChainPay {
    
    // State variables
    address payable public owner;
    uint256 public transactionCounter;
    uint256 public platformFeePercentage; // Fee in basis points (100 = 1%)
    uint256 private constant MAX_FEE = 1000; // Maximum 10% fee
    uint256 private constant MAX_PAYMENT_HISTORY = 1000; // Prevent DoS
    bool private locked; // Reentrancy guard
    
    // Structs
    struct Payment {
        uint256 id;
        address sender;
        address receiver;
        uint256 amount;
        uint256 feeCharged;
        uint256 timestamp;
        bool completed;
        string description;
    }
    
    // Mappings
    mapping(uint256 => Payment) public payments;
    mapping(address => uint256[]) private userPayments;
    mapping(address => uint256) public userBalance;
    
    // Events
    event PaymentSent(
        uint256 indexed paymentId,
        address indexed sender,
        address indexed receiver,
        uint256 totalAmount,
        uint256 amountAfterFee,
        uint256 fee,
        uint256 timestamp
    );
    
    event PaymentWithdrawn(
        address indexed user,
        uint256 amount,
        uint256 timestamp
    );
    
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    
    event EmergencyWithdrawal(
        address indexed user,
        uint256 amount,
        uint256 timestamp
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier validAddress(address _addr) {
        require(_addr != address(0), "Invalid address");
        _;
    }
    
    modifier noReentrancy() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }
    
    // Constructor
    constructor(uint256 _feePercentage) {
        require(_feePercentage <= MAX_FEE, "Fee exceeds maximum");
        owner = payable(msg.sender);
        platformFeePercentage = _feePercentage;
        transactionCounter = 0;
        locked = false;
    }
    
    /**
     * @dev Core Function 1: Send payment to another address
     * @param _receiver Address of the payment receiver
     * @param _description Description or memo for the payment
     */
    function sendPayment(address _receiver, string memory _description) 
        external 
        payable 
        validAddress(_receiver) 
        noReentrancy
    {
        require(msg.value > 0, "Payment amount must be greater than 0");
        require(_receiver != msg.sender, "Cannot send payment to yourself");
        
        // Prevent integer overflow in fee calculation
        require(
            msg.value <= type(uint256).max / platformFeePercentage, 
            "Payment amount too large"
        );
        
        // Check payment history limit to prevent DoS
        require(
            userPayments[msg.sender].length < MAX_PAYMENT_HISTORY &&
            userPayments[_receiver].length < MAX_PAYMENT_HISTORY,
            "Payment history limit reached"
        );
        
        // Calculate platform fee
        uint256 fee = (msg.value * platformFeePercentage) / 10000;
        uint256 amountAfterFee = msg.value - fee;
        
        // Increment counter first (CEI pattern)
        transactionCounter++;
        
        // Create payment record
        payments[transactionCounter] = Payment({
            id: transactionCounter,
            sender: msg.sender,
            receiver: _receiver,
            amount: amountAfterFee,
            feeCharged: fee,
            timestamp: block.timestamp,
            completed: true,
            description: _description
        });
        
        // Update user payment history
        userPayments[msg.sender].push(transactionCounter);
        userPayments[_receiver].push(transactionCounter);
        
        // Credit receiver balance
        userBalance[_receiver] += amountAfterFee;
        
        // Credit platform fee to owner
        userBalance[owner] += fee;
        
        emit PaymentSent(
            transactionCounter,
            msg.sender,
            _receiver,
            msg.value,
            amountAfterFee,
            fee,
            block.timestamp
        );
    }
    
    /**
     * @dev Core Function 2: Withdraw available balance (Reentrancy Protected)
     */
    function withdrawBalance() external noReentrancy {
        uint256 balance = userBalance[msg.sender];
        require(balance > 0, "No balance available to withdraw");
        
        // Checks-Effects-Interactions (CEI) pattern
        // Reset balance BEFORE transfer to prevent reentrancy
        userBalance[msg.sender] = 0;
        
        // Transfer funds
        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Withdrawal failed");
        
        emit PaymentWithdrawn(msg.sender, balance, block.timestamp);
    }
    
    /**
     * @dev Core Function 3: Get payment history for a user (Paginated)
     * @param _user Address of the user
     * @param _offset Starting index
     * @param _limit Maximum number of records to return
     * @return Array of payment IDs associated with the user
     */
    function getPaymentHistory(address _user, uint256 _offset, uint256 _limit) 
        external 
        view 
        validAddress(_user) 
        returns (uint256[] memory) 
    {
        uint256[] storage allPayments = userPayments[_user];
        uint256 totalPayments = allPayments.length;
        
        if (_offset >= totalPayments) {
            return new uint256[](0);
        }
        
        uint256 end = _offset + _limit;
        if (end > totalPayments) {
            end = totalPayments;
        }
        
        uint256 resultLength = end - _offset;
        uint256[] memory result = new uint256[](resultLength);
        
        for (uint256 i = 0; i < resultLength; i++) {
            result[i] = allPayments[_offset + i];
        }
        
        return result;
    }
    
    /**
     * @dev Get total payment count for a user
     * @param _user Address of the user
     */
    function getPaymentCount(address _user) 
        external 
        view 
        validAddress(_user) 
        returns (uint256) 
    {
        return userPayments[_user].length;
    }
    
    /**
     * @dev Get payment details by ID
     * @param _paymentId ID of the payment
     */
    function getPaymentDetails(uint256 _paymentId) 
        external 
        view 
        returns (
            uint256 id,
            address sender,
            address receiver,
            uint256 amount,
            uint256 feeCharged,
            uint256 timestamp,
            bool completed,
            string memory description
        ) 
    {
        require(_paymentId > 0 && _paymentId <= transactionCounter, "Invalid payment ID");
        Payment memory p = payments[_paymentId];
        return (
            p.id, 
            p.sender, 
            p.receiver, 
            p.amount, 
            p.feeCharged,
            p.timestamp, 
            p.completed, 
            p.description
        );
    }
    
    /**
     * @dev Update platform fee percentage (only owner)
     * @param _newFeePercentage New fee percentage in basis points
     */
    function updatePlatformFee(uint256 _newFeePercentage) external onlyOwner {
        require(_newFeePercentage <= MAX_FEE, "Fee cannot exceed 10%");
        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = _newFeePercentage;
        emit FeeUpdated(oldFee, _newFeePercentage);
    }
    
    /**
     * @dev Emergency withdrawal function (only owner)
     * @param _user Address of the user whose balance to withdraw
     * @notice Only use in extreme circumstances (contract upgrade/pause)
     */
    function emergencyWithdraw(address _user) 
        external 
        onlyOwner 
        validAddress(_user)
        noReentrancy
    {
        uint256 balance = userBalance[_user];
        require(balance > 0, "No balance to withdraw");
        
        userBalance[_user] = 0;
        
        (bool success, ) = payable(_user).call{value: balance}("");
        require(success, "Emergency withdrawal failed");
        
        emit EmergencyWithdrawal(_user, balance, block.timestamp);
    }
    
    /**
     * @dev Transfer ownership to new address
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address payable _newOwner) 
        external 
        onlyOwner 
        validAddress(_newOwner) 
    {
        require(_newOwner != owner, "Already the owner");
        owner = _newOwner;
    }
    
    /**
     * @dev Get contract balance
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Get user's available balance
     * @param _user Address of the user
     */
    function getUserBalance(address _user) external view returns (uint256) {
        return userBalance[_user];
    }
    
    /**
     * @dev Get maximum payment history limit
     */
    function getMaxPaymentHistory() external pure returns (uint256) {
        return MAX_PAYMENT_HISTORY;
    }
}















