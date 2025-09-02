const express = require("express");
const cors = require("cors");
const { ethers } = require("ethers");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Step 1: Load All Environment Variables ---
const { 
  MONGO_URI, 
  ACCREDITATION_BODY_PRIVATE_KEY, 
  ADMIN_SECRET_KEY, 
  BSC_RPC, 
  CONTRACT_ADDRESS,
  JWT_SECRET 
} = process.env;

// --- Step 2: Validate Environment Variables ---
if (!MONGO_URI || !ACCREDITATION_BODY_PRIVATE_KEY || !ADMIN_SECRET_KEY || !BSC_RPC || !CONTRACT_ADDRESS || !JWT_SECRET) {
    console.error("❌ Fatal Error: One or more environment variables are missing in your backend/.env file.");
    console.error("Please ensure MONGO_URI, ACCREDITATION_BODY_PRIVATE_KEY, ADMIN_SECRET_KEY, BSC_RPC, CONTRACT_ADDRESS, and JWT_SECRET are all set.");
    process.exit(1);
}

// --- Step 3: Initialize Wallets and Connections ---
const accreditationSigner = new ethers.Wallet(ACCREDITATION_BODY_PRIVATE_KEY);
mongoose.connect(MONGO_URI).then(() => console.log("✅ MongoDB connected")).catch(err => console.error("❌ MongoDB connection error:", err));
const provider = new ethers.JsonRpcProvider(BSC_RPC);
const contractABI = require("./AccreditationRegistryABI.json").abi;
const contract = new ethers.Contract(CONTRACT_ADDRESS, contractABI, provider);

// --- Step 4: Define Mongoose Schemas ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    collegeAddress: { type: String, default: null },
    role: { type: String, enum: ['college', 'student'], default: 'student' }
}, { timestamps: true });

const AccreditationRequest = mongoose.model("AccreditationRequest", new mongoose.Schema({
    collegeAddress: { type: String, unique: true, index: true },
    collegeName: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    proof: Object,
    signature: String,
}, { timestamps: true }));

const Certificate = mongoose.model("Certificate", new mongoose.Schema({
    certificateId: { type: String, unique: true, index: true },
    studentName: String,
    course: String,
    rollNo: String,
    dateOfIssuing: String,
    issuedBy: String,
    issuedAt: Number,
    txHash: String,
}, { versionKey: false }));

const User = mongoose.model("User", UserSchema);

console.log("--- Server Configuration ---");
console.log(`✅ Accreditation Body Address: ${accreditationSigner.address}`);
console.log(`✅ Connected to Contract: ${CONTRACT_ADDRESS}`);
console.log("--------------------------");

// --- Middleware for JWT Authentication ---
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// --- Step 5: Define All API Endpoints ---

// Authentication Endpoints
app.post("/api/signup", async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: "User with this username or email already exists" });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role: role || 'student'
        });
        
        await newUser.save();
        
        console.log(`🔔 New user registered: ${username} (Role: ${newUser.role})`);

        if (newUser.role === 'student') {
            const token = jwt.sign(
                { 
                    userId: newUser._id, 
                    username: newUser.username, 
                    email: newUser.email,
                    collegeAddress: newUser.collegeAddress,
                    role: newUser.role
                }, 
                JWT_SECRET, 
                { expiresIn: '1h' }
            );
            return res.status(201).json({ 
                message: "Student registered successfully.",
                token,
                role: newUser.role
            });
        }
        
        res.status(201).json({ message: "College registered successfully. Please link your wallet." });
    } catch (err) {
        console.error("Error in /api/signup:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: "Invalid username or password" });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid username or password" });
        }
        
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username, 
                email: user.email,
                collegeAddress: user.collegeAddress,
                role: user.role
            }, 
            JWT_SECRET, 
            { expiresIn: '1h' }
        );
        
        console.log(`🔑 User logged in: ${username} (Role: ${user.role})`);
        res.json({ 
            message: "Login successful", 
            token,
            collegeAddress: user.collegeAddress,
            role: user.role
        });
    } catch (error) {
        console.error("Error in /api/login:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/link-wallet", async (req, res) => {
    try {
        const { email, walletAddress } = req.body;
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        
        user.collegeAddress = walletAddress;
        await user.save();
        
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username,
                email: user.email, 
                collegeAddress: walletAddress,
                role: user.role
            }, 
            JWT_SECRET, 
            { expiresIn: '1h' }
        );
        
        console.log(`🔗 Wallet linked for user: ${email} -> ${walletAddress}`);
        res.json({ 
            message: "Wallet linked successfully", 
            token,
            collegeAddress: walletAddress,
            role: user.role
        });
    } catch (err) {
        console.error("Error in /api/link-wallet:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get("/api/user", authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(user);
    } catch (err) {
        console.error("Error in /api/user:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/request-accreditation", authenticateJWT, async (req, res) => {
    try {
        const { collegeAddress, collegeName } = req.body;
        
        if (req.user.role !== 'college') {
            return res.status(403).json({ error: "Unauthorized: Only colleges can request accreditation." });
        }
        if (req.user.collegeAddress.toLowerCase() !== collegeAddress.toLowerCase()) {
            return res.status(403).json({ error: "Unauthorized: You can only submit requests for your own address" });
        }
        
        if (!collegeAddress || !collegeName) return res.status(400).json({ error: "collegeAddress and collegeName are required." });
        
        const existing = await AccreditationRequest.findOne({ collegeAddress });
        if (existing) return res.status(400).json({ error: `A request for this address already exists with status: ${existing.status}` });
        
        const newRequest = new AccreditationRequest({ collegeAddress, collegeName });
        await newRequest.save();
        
        console.log(`🔔 New pending request from ${collegeName} (${collegeAddress})`);
        res.status(201).json({ message: "Request submitted successfully. It is now pending review." });
    } catch (err) {
        console.error("Error in /api/request-accreditation:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/admin/approve-request", async (req, res) => {
    try {
        const { requestId, secretKey } = req.body;
        if (secretKey !== ADMIN_SECRET_KEY) return res.status(403).json({ error: "Unauthorized" });
        
        const request = await AccreditationRequest.findById(requestId);
        if (!request || request.status !== 'pending') return res.status(404).json({ error: "No pending request found with this ID." });
        
        const validUntil = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // 1 year
        const domain = { name: "AccreditationRegistry", version: "1", chainId: 97, verifyingContract: CONTRACT_ADDRESS };
        const types = { ProofOfAccreditation: [{ name: "college", type: "address" }, { name: "collegeName", type: "string" }, { name: "validUntil", type: "uint256" }] };
        const value = { college: request.collegeAddress, collegeName: request.collegeName, validUntil };
        const signature = await accreditationSigner.signTypedData(domain, types, value);
        
        request.status = 'approved';
        request.proof = value;
        request.signature = signature;
        await request.save();
        
        console.log(`✅ Approved request for ${request.collegeName}`);
        res.json({ message: "Request approved successfully.", request });
    } catch (err) {
        console.error("Error in /api/admin/approve-request:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/admin/reject-request", async (req, res) => {
    try {
        const { requestId, secretKey } = req.body;
        if (secretKey !== ADMIN_SECRET_KEY) return res.status(403).json({ error: "Unauthorized" });
        
        const request = await AccreditationRequest.findById(requestId);
        if (!request || request.status !== 'pending') return res.status(404).json({ error: "No pending request found with this ID." });
        
        request.status = 'rejected';
        await request.save();
        
        console.log(`❌ Rejected request for ${request.collegeName}`);
        res.json({ message: "Request rejected successfully." });
    } catch (err) {
        console.error("Error in /api/admin/reject-request:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get("/api/check-status/:collegeAddress", authenticateJWT, async (req, res) => {
    try {
        if (req.user.role !== 'college') {
            return res.status(403).json({ error: "Unauthorized: Only colleges can check accreditation status." });
        }
        if (req.user.collegeAddress.toLowerCase() !== req.params.collegeAddress.toLowerCase()) {
            return res.status(403).json({ error: "Unauthorized: You can only check your own status" });
        }
        
        const request = await AccreditationRequest.findOne({ collegeAddress: req.params.collegeAddress });
        if (!request) return res.status(404).json({ status: 'not_found' });
        
        res.json({ status: request.status, proof: request.proof, signature: request.signature });
    } catch (err) {
        console.error("Error in /api/check-status:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/check-duplicate", authenticateJWT, async (req, res) => {
    try {
        const { collegeAddress, rollNo } = req.body;
        
        if (req.user.role !== 'college') {
            return res.status(403).json({ error: "Unauthorized: Only colleges can check for duplicates." });
        }
        if (req.user.collegeAddress.toLowerCase() !== collegeAddress.toLowerCase()) {
            return res.status(403).json({ error: "Unauthorized: You can only check duplicates for your own college" });
        }
        
        if (!collegeAddress || !rollNo) return res.status(400).json({ error: "collegeAddress and rollNo are required" });
        
        const contentHash = ethers.solidityPackedKeccak256(["address", "string"], [collegeAddress, rollNo.toLowerCase()]);
        const isIssued = await contract.isCertificateIssued(contentHash);
        
        if (isIssued) return res.json({ isDuplicate: true, message: "A certificate for this roll number has already been issued by your college." });
        res.json({ isDuplicate: false });
    } catch (err) {
        console.error("Error in /api/check-duplicate:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/api/sync", authenticateJWT, async (req, res) => {
    try {
        const { certificateId, txHash } = req.body;
        const certData = await contract.getCertificate(certificateId);
        const [id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt, exists] = certData;
        
        if (!exists) return res.status(404).json({ error: 'Certificate not found on-chain during sync.' });
        
        if (req.user.role !== 'college') {
            return res.status(403).json({ error: "Unauthorized: Only colleges can sync certificates." });
        }
        if (req.user.collegeAddress.toLowerCase() !== issuedBy.toLowerCase()) {
            return res.status(403).json({ error: "Unauthorized: You can only sync certificates issued by your college" });
        }
        
        const newCert = new Certificate({ 
            certificateId: id, studentName, course, rollNo, dateOfIssuing, issuedBy, 
            issuedAt: Number(issuedAt), txHash 
        });
        
        await newCert.save();
        res.json({ success: true, certificate: newCert });
    } catch (err) {
        console.error("Error in /api/sync:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// MODIFIED: This endpoint now handles the entire verification flow automatically.
app.get("/api/verify/:certificateId", async (req, res) => {
    try {
        const { certificateId } = req.params;
        
        // 1. Check database cache first
        const cachedCert = await Certificate.findOne({ certificateId });
        if (cachedCert) {
            return res.json({ valid: true, source: 'cache', certificate: cachedCert });
        }
        
        // 2. If not in cache, automatically fetch from blockchain
        const onChainCert = await contract.getCertificate(certificateId);
        const [id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt, exists] = onChainCert;
        
        if (exists) {
            const newCertData = { 
                certificateId: id, studentName, course, rollNo, dateOfIssuing, issuedBy, 
                issuedAt: Number(issuedAt) 
            };
            
            // 3. Save the fetched certificate to the cache for future requests
            await Certificate.findOneAndUpdate({ certificateId: id }, newCertData, { upsert: true });
            
            return res.json({ valid: true, source: 'blockchain', certificate: newCertData });
        }
        
        // 4. If not found anywhere, return an error
        res.status(404).json({ valid: false, message: "Certificate not found in database or on the blockchain." });
    } catch (err) {
        console.error("Error in /api/verify:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// --- Step 6: Start the Server ---
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`✅ Server is now running on port ${PORT}`));