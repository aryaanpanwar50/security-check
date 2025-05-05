import { useState } from "react";
import axios from 'axios';
import { Shield, AlertTriangle, FileText } from "lucide-react";

export default function Home() {
    const [url, setUrl] = useState('');
    const [report, setReport] = useState(null);

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    async function runScan(scanType) {
        setError('');
        setReport(null);

        
        if (!url || !/^https?:\/\/.+/.test(url)) {
            setError('Please enter a valid URL');
            return;
        }

        setLoading(true);
        try {
            const res = await axios.post(`https://security-check-qgnx.onrender.com/api/scan/${scanType}`, 
                { url },
                { timeout: 30000 }
            );
            if (res.data.error) {
                setError(res.data.error);
                return;
            }
            setReport(res.data.report);
            
        } catch (err) {
            setError(err.response?.data?.error || 'Scan failed - please try again');
        } finally {
            setLoading(false);
        }
    }

    // Helper function for severity colors
    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'high': return 'text-red-600 bg-red-50';
            case 'medium': return 'text-orange-500 bg-orange-50';
            case 'low': return 'text-yellow-500 bg-yellow-50';
            default: return 'text-gray-500 bg-gray-50';
        }
    }

    return (
        <div className="min-h-screen bg-gray-50 p-6">
            <div className="max-w-4xl mx-auto bg-white rounded-lg shadow-md p-6">
                <h1 className="text-2xl font-bold text-gray-800 mb-6 flex items-center">
                    <Shield className="w-6 h-6 text-indigo-600 mr-2" />
                    Website Security Scanner
                </h1>
                
                {error && (
                    <div className="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 mb-4 rounded">
                        <div className="flex items-center">
                            <AlertTriangle className="w-5 h-5 mr-2" />
                            Error: {error}
                        </div>
                    </div>
                )}
                
                <div>
                    <input 
                        value={url} 
                        onChange={e => setUrl(e.target.value)} 
                        placeholder="https://example.com" 
                        className="w-3/5 p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    />
                    <div className="mt-3">
                        <button 
                            onClick={() => runScan('light')} 
                            disabled={loading}
                            className="px-4 py-2 bg-indigo-100 text-indigo-700 rounded-md hover:bg-indigo-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 transition duration-150"
                        >
                            Run Light Scan
                        </button>
                        <button 
                            onClick={() => runScan('medium')} 
                            disabled={loading} 
                            className="ml-3 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 transition duration-150"
                        >
                            Run Medium Scan
                        </button>
                    </div>
                </div>

                {loading && (
                    <p className="mt-4 flex items-center text-gray-600">
                        <span className="inline-block w-4 h-4 border-t-2 border-indigo-600 rounded-full animate-spin mr-2"></span>
                        Scanning...
                    </p>
                )}

                

                {report && (
                    <div className="mt-8">
                        <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                            <FileText className="mr-2 text-indigo-600" /> Technical Report
                        </h2>
                        <ul className="space-y-4">
                            {report.map((r, i) => (
                                <li key={i} className="mb-4 border border-gray-200 rounded-lg overflow-hidden">
                                    <div className="p-4">
                                        <div className="flex justify-between items-center mb-2">
                                            <strong className="text-gray-800">{r.vulnerability}</strong>
                                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(r.severity)}`}>
                                                {r.severity}
                                            </span>
                                        </div>
                                        Tool: {r.tool}<br />
                                        Evidence: <pre className="mt-2 bg-gray-50 p-3 rounded border border-gray-200 font-mono text-sm overflow-x-auto">{r.evidence}</pre>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
}