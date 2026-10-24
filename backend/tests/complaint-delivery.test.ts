import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const baseComplaint = {
  id: "11111111-1111-4111-8111-111111111111",
  investigation_id: "22222222-2222-4222-8222-222222222222",
  brand_id: "33333333-3333-4333-8333-333333333333",
  complaint_type: "registrar_abuse",
  recipient_email: "abuse@registrar.example",
  target_url: "https://nexusp4y-login.top/verify",
  status: "generated",
  subject: "Abuse notice",
  body_text: "Full notice body",
  metadata: {},
  sent_at: null,
  created_at: "2026-10-24T00:00:00Z",
  updated_at: "2026-10-24T00:00:00Z",
};

const queryMock = vi.fn();
const recordLogMock = vi.fn();
const sendMailMock = vi.fn();

vi.mock("../src/db", () => ({
  query: (...args: unknown[]) => queryMock(...args),
  withTransaction: vi.fn(),
  pool: { query: vi.fn() },
}));

vi.mock("../src/repositories", () => ({
  AuditLogsRepository: {
    recordLog: (...args: unknown[]) => recordLogMock(...args),
  },
}));

vi.mock("nodemailer", () => ({
  default: {
    createTransport: () => ({ sendMail: (...args: unknown[]) => sendMailMock(...args) }),
  },
}));

describe("Complaint delivery", () => {
  beforeEach(() => {
    queryMock.mockReset();
    recordLogMock.mockReset().mockResolvedValue(undefined);
    sendMailMock.mockReset();
    vi.stubEnv("SMTP_HOST", "");
    vi.stubEnv("SMTP_USER", "");
    vi.stubEnv("SMTP_PASS", "");
    vi.stubEnv("COMPLAINT_FROM_EMAIL", "");
    vi.stubEnv("COMPLAINT_WEBHOOK_URL", "");
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("does not claim delivery when no transport is configured", async () => {
    queryMock.mockResolvedValue({ rows: [baseComplaint] });

    const { ComplaintDispatchService } = await import("../src/complaints-dispatch.service");
    const service = new ComplaintDispatchService();

    const { result } = await service.deliver(baseComplaint.id);

    expect(result.status).toBe("not_configured");
    expect(result.deliveredAt).toBeNull();
    // One read, then one update that records the attempt while staying "generated".
    expect(queryMock).toHaveBeenCalledTimes(2);
    expect(String(queryMock.mock.calls[0]?.[0])).toContain("SELECT");

    const updateCall = queryMock.mock.calls.find((call) => String(call[0]).includes("UPDATE complaints"));
    expect(updateCall?.[1]?.[1]).toBe("generated");
    expect(String(updateCall?.[0])).toContain("submission_status");
  });

  it("marks the complaint sent only after SMTP accepts the message", async () => {
    vi.stubEnv("SMTP_HOST", "smtp.example.com");
    vi.stubEnv("SMTP_USER", "robot@nexuspay.io");
    vi.stubEnv("SMTP_PASS", "secret");
    vi.stubEnv("COMPLAINT_FROM_EMAIL", "security@nexuspay.io");

    queryMock
      .mockResolvedValueOnce({ rows: [baseComplaint] })
      .mockImplementationOnce(async (_sql: string, params: unknown[]) => ({
        rows: [{ ...baseComplaint, status: "sent", sent_at: "2026-10-24T10:00:00Z", metadata: params?.[2] }],
      }));
    sendMailMock.mockResolvedValue({ messageId: "<abc@example.com>" });

    const { ComplaintDispatchService, resetTransporterCache } = await import(
      "../src/complaints-dispatch.service"
    );
    resetTransporterCache();
    const service = new ComplaintDispatchService();

    const { result, complaint } = await service.deliver(baseComplaint.id);

    expect(sendMailMock).toHaveBeenCalledTimes(1);
    expect(sendMailMock.mock.calls[0]?.[0]).toMatchObject({
      to: "abuse@registrar.example",
      subject: "Abuse notice",
    });
    expect(result.status).toBe("sent");
    expect(result.providerMessageId).toBe("<abc@example.com>");
    expect(complaint?.status).toBe("sent");

    const updateCall = queryMock.mock.calls.find((call) => String(call[0]).includes("UPDATE complaints"));
    expect(updateCall?.[1]?.[1]).toBe("sent");
    expect(recordLogMock).toHaveBeenCalledWith(
      expect.objectContaining({ status: "DELIVERED", source: "complaint:smtp" }),
    );
  });

  it("reports a failure and keeps the complaint unsent when SMTP rejects", async () => {
    vi.stubEnv("SMTP_HOST", "smtp.example.com");
    vi.stubEnv("COMPLAINT_FROM_EMAIL", "security@nexuspay.io");

    queryMock
      .mockResolvedValueOnce({ rows: [baseComplaint] })
      .mockImplementationOnce(async (_sql: string, params: unknown[]) => ({
        rows: [{ ...baseComplaint, status: "generated", metadata: params?.[2] }],
      }));
    sendMailMock.mockRejectedValue(new Error("550 mailbox unavailable"));

    const { ComplaintDispatchService, resetTransporterCache } = await import(
      "../src/complaints-dispatch.service"
    );
    resetTransporterCache();
    const service = new ComplaintDispatchService();

    const { result } = await service.deliver(baseComplaint.id);

    expect(result.status).toBe("failed");
    expect(result.detail).toContain("550");

    const updateCall = queryMock.mock.calls.find((call) => String(call[0]).includes("UPDATE complaints"));
    expect(updateCall?.[1]?.[1]).toBe("generated");
    expect(recordLogMock).toHaveBeenCalledWith(expect.objectContaining({ status: "FAILED" }));
  });

  it("uses the HTTP relay when no SMTP server is configured", async () => {
    vi.stubEnv("COMPLAINT_WEBHOOK_URL", "https://relay.example.com/send");
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ messageId: "relay-1" }), {
        status: 202,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    queryMock
      .mockResolvedValueOnce({ rows: [baseComplaint] })
      .mockImplementationOnce(async (_sql: string, params: unknown[]) => ({
        rows: [{ ...baseComplaint, status: "sent", metadata: params?.[2] }],
      }));

    const { ComplaintDispatchService } = await import("../src/complaints-dispatch.service");
    const service = new ComplaintDispatchService();

    const { result } = await service.deliver(baseComplaint.id);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.status).toBe("sent");
    expect(result.transport).toBe("webhook");
    expect(result.providerMessageId).toBe("relay-1");
  });

  it("does not re-send an already submitted notice", async () => {
    queryMock.mockResolvedValue({ rows: [{ ...baseComplaint, status: "sent", sent_at: "2026-10-24T09:00:00Z" }] });

    const { ComplaintDispatchService } = await import("../src/complaints-dispatch.service");
    const service = new ComplaintDispatchService();

    const { result } = await service.deliver(baseComplaint.id);

    expect(result.status).toBe("sent");
    expect(result.detail).toContain("already been submitted");
    expect(queryMock).toHaveBeenCalledTimes(1);
  });
});
