// backend/server.js - The Complete and Final Version

const express = require("express");
const cors = require("cors");
const { ethers } = require("ethers");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Step 1: Load All Environment Variables ---
const { MONGO_URI, ACCREDITATION_BODY_PRIVATE_KEY, ADMIN_SECRET_KEY, BSC_RPC, CONTRACT_ADDRESS } = process.env;

// --- Step 2: Validate Environment Variables ---
if (!MONGO_URI || !ACCREDITATION_BODY_PRIVATE_KEY || !ADMIN_SECRET_KEY || !BSC_RPC || !CONTRACT_ADDRESS) {
    console.error("❌ Fatal Error: One or more environment variables are missing in your backend/.env file.");
    console.error("Please ensure MONGO_URI, ACCREDITATION_BODY_PRIVATE_KEY, ADMIN_SECRET_KEY, BSC_RPC, and CONTRACT_ADDRESS are all set.");
    process.exit(1);
}

// --- Step 3: Initialize Wallets and Connections ---
const accreditationSigner = new ethers.Wallet(ACCREDITATION_BODY_PRIVATE_KEY);
mongoose.connect(MONGO_URI).then(() => console.log("✅ MongoDB connected")).catch(err => console.error("❌ MongoDB connection error:", err));

const provider = new ethers.JsonRpcProvider(BSC_RPC);
const contractABI = require("./AccreditationRegistryABI.json").abi;
const contract = new ethers.Contract(CONTRACT_ADDRESS, contractABI, provider);

// --- Step 4: Define Mongoose Schemas ---
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

console.log("--- Server Configuration ---");
console.log(`✅ Accreditation Body Address: ${accreditationSigner.address}`);
console.log(`✅ Connected to Contract: ${CONTRACT_ADDRESS}`);
console.log("--------------------------");


// --- Step 5: Define All API Endpoints ---

// A College submits a request for accreditation
app.post("/api/request-accreditation", async (req, res) => {
    try {
        const { collegeAddress, collegeName } = req.body;
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

// The Admin approves a pending request
app.post("/api/admin/approve-request", async (req, res) => {
    try {
        const { requestId, secretKey } = req.body;
        if (secretKey !== ADMIN_SECRET_KEY) return res.status(403).json({ error: "Unauthorized" });
        const request = await AccreditationRequest.findById(requestId);
        if (!request || request.status !== 'pending') return res.status(404).json({ error: "No pending request found with this ID." });
        
        const validUntil = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // Valid for 1 year
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

// The Admin rejects a pending request
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

// A College checks the status of their request
app.get("/api/check-status/:collegeAddress", async (req, res) => {
    try {
        const request = await AccreditationRequest.findOne({ collegeAddress: req.params.collegeAddress });
        if (!request) return res.status(404).json({ status: 'not_found' });
        res.json({ status: request.status, proof: request.proof, signature: request.signature });
    } catch (err) {
        console.error("Error in /api/check-status:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// A College checks for certificate duplicates before issuing
app.post("/api/check-duplicate", async (req, res) => {
    try {
        const { collegeAddress, rollNo } = req.body;
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

// The Frontend syncs a new certificate to the DB cache
app.post("/api/sync", async (req, res) => {
    try {
        const { certificateId, txHash } = req.body;
        const certData = await contract.getCertificate(certificateId);
        const [id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt, exists] = certData;
        if (!exists) return res.status(404).json({ error: 'Certificate not found on-chain during sync.' });
        const newCert = new Certificate({ certificateId: id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt: Number(issuedAt), txHash });
        await newCert.save();
        res.json({ success: true, certificate: newCert });
    } catch (err) {
        console.error("Error in /api/sync:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Anyone verifies a certificate (cache-first)
app.get("/api/verify/:certificateId", async (req, res) => {
    try {
        const { certificateId } = req.params;
        const cachedCert = await Certificate.findOne({ certificateId });
        if (cachedCert) return res.json({ valid: true, source: 'cache', certificate: cachedCert });
        
        const onChainCert = await contract.getCertificate(certificateId);
        const [id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt, exists] = onChainCert;
        
        if (exists) {
            const newCert = new Certificate({ certificateId: id, studentName, course, rollNo, dateOfIssuing, issuedBy, issuedAt: Number(issuedAt) });
            await newCert.save();
            return res.json({ valid: true, source: 'blockchain', certificate: newCert });
        }
        res.status(404).json({ valid: false, message: "Certificate not found." });
    } catch (err) {
        console.error("Error in /api/verify:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// --- Step 6: Start the Server ---
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`✅ Server is now running on port ${PORT}`));