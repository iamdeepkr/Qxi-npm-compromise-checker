// This is a test file to demonstrate malicious URL detection
// DO NOT USE IN PRODUCTION - CONTAINS SIMULATED MALICIOUS CONTENT

const express = require('express');
const app = express();

// Simulated malicious content for testing detection
const config = {
    // This would trigger URL detection
    supportEmail: 'support@npmjs.help',
    helpDomain: 'npmjs.help',
    
    // Crypto-related keywords that should be detected
    walletTypes: ['metamask', 'coinbase', 'ledger'],
    cryptoAssets: ['bitcoin', 'ethereum', 'cryptocurrency'],
    
    // Suspicious patterns
    obfuscatedCode: String.fromCharCode(72, 101, 108, 108, 111),
    encodedData: btoa('suspicious data'),
};

// Browser-specific APIs that might indicate malicious activity
if (typeof window !== 'undefined') {
    // This code would only run in browser environment
    const walletData = localStorage.getItem('wallet');
    const privateKeys = sessionStorage.getItem('private key');
    
    // Simulated crypto wallet interaction
    if (window.ethereum) {
        console.log('Web3 wallet detected');
    }
}

app.get('/', (req, res) => {
    res.send('Test application with simulated malicious indicators');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
