"use client";

import { Suspense, useEffect, useState, useRef } from "react";
import { askAI, getChatHistory, listJobs, type Job } from "@/lib/api";
import { useJobSelection } from "@/hooks/useJobSelection";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp?: string;
}

const SUGGESTED_QUESTIONS = [
  "Did any brute force attack happen?",
  "Which IP address is most suspicious and why?",
  "Was there a successful login after failed attempts?",
  "What are the top security concerns in this log?",
  "Summarize this log for management.",
  "Are there any signs of data exfiltration?",
  "What MITRE ATT&CK techniques were used?",
  "What should we do to remediate the threats found?",
];

export default function InvestigationPage() {
  return <Suspense fallback={<div className="px-6 py-20 text-center text-slate-400">Loading...</div>}><InvestigationContent /></Suspense>;
}

function InvestigationContent() {
  const { selectedJob, setSelectedJob } = useJobSelection();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listJobs().then((d) => setJobs(d.jobs)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedJob) return;
    getChatHistory(selectedJob)
      .then((d) => setMessages(d.messages.map((m) => ({ role: m.role as "user" | "assistant", content: m.content, timestamp: m.timestamp }))))
      .catch(() => {});
  }, [selectedJob]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async (question: string) => {
    if (!selectedJob || !question.trim()) return;
    const newMessages: Message[] = [...messages, { role: "user", content: question }];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    try {
      const res = await askAI(selectedJob, question);
      setMessages([...newMessages, { role: "assistant", content: res.answer }]);
    } catch (err: unknown) {
      setMessages([
        ...newMessages,
        { role: "assistant", content: `Error: ${err instanceof Error ? err.message : "Failed to get response"}` },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="border-b border-slate-700/50 px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Investigation Assistant</h1>
          <p className="text-sm text-slate-400">Ask questions about the analyzed logs</p>
        </div>
        <select
          className="input w-64"
          value={selectedJob}
          onChange={(e) => {
            setSelectedJob(e.target.value);
            setMessages([]);
          }}
        >
          <option value="">Select job...</option>
          {jobs.map((j) => <option key={j.id} value={j.id}>{j.filename}</option>)}
        </select>
      </div>

      {/* Chat Area */}
      <div className="flex-1 overflow-y-auto px-6 py-6 space-y-4">
        {messages.length === 0 && selectedJob && (
          <div className="text-center py-10">
            <p className="text-slate-400 mb-6">Start by asking a question about the log analysis</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-2xl mx-auto">
              {SUGGESTED_QUESTIONS.map((q, i) => (
                <button
                  key={i}
                  className="btn-secondary text-left text-sm"
                  onClick={() => sendMessage(q)}
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div className={`max-w-[75%] rounded-2xl px-5 py-3 ${
              msg.role === "user"
                ? "bg-blue-600 text-white"
                : "card"
            }`}>
              <p className="text-sm whitespace-pre-line">{msg.content}</p>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="card px-5 py-3">
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Analyzing logs...
              </div>
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Input */}
      {selectedJob && (
        <div className="border-t border-slate-700/50 px-6 py-4">
          <div className="flex gap-3 max-w-4xl mx-auto">
            <input
              type="text"
              className="input flex-1"
              placeholder="Ask about the logs... e.g., 'Which IP is most suspicious?'"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !loading && sendMessage(input)}
              disabled={loading}
            />
            <button
              className="btn-primary px-6"
              onClick={() => sendMessage(input)}
              disabled={!input.trim() || loading}
            >
              Send
            </button>
          </div>
        </div>
      )}

      {!selectedJob && (
        <div className="text-center py-20">
          <p className="text-slate-400 text-lg">Select an analysis job to start investigating</p>
          <a href="/" className="btn-primary mt-4 inline-flex">Upload a Log File</a>
        </div>
      )}
    </div>
  );
}
