import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import axios from 'axios';
import dotenv from 'dotenv';
import { randomBytes, randomInt, randomUUID, scryptSync, timingSafeEqual, createHash, createHmac } from 'crypto';
import mongoose, { Schema, model } from 'mongoose';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';
import { clerkMiddleware, createClerkClient, getAuth } from '@clerk/express';
import { Resend } from 'resend';
import validator from 'validator';
import { body, validationResult } from 'express-validator';

dotenv.config();
mongoose.set('bufferCommands', false);

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 8080);
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'https://kcwebsite-rho.vercel.app';
const NKWA_BASE_URL = process.env.NKWA_BASE_URL || 'https://api.mynkwa.com';
const NKWA_API_KEY = process.env.NKWA_API_KEY || '';
const APP_BASE_URL = process.env.APP_BASE_URL || CORS_ORIGIN;
const BACKEND_PUBLIC_URL = process.env.BACKEND_PUBLIC_URL || `http://localhost:${PORT}`;
const APP_AUTH_SECRET = process.env.APP_AUTH_SECRET || 'dev-only-secret-change-in-prod';
const resend = new Resend(process.env.RESEND_API_KEY || '');
const EMAIL_FROM = process.env.EMAIL_FROM || 'Knowledge Center <onboarding@resend.dev>';
const clerkClient = createClerkClient({ secretKey: process.env.CLERK_SECRET_KEY || '' });
const ADMIN_EMAIL_ALLOWLIST = (process.env.ADMIN_EMAIL_ALLOWLIST || '')
  .split(',')
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';

if (process.env.NODE_ENV === 'production') {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
  }));
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts, please try again later.' },
});
const blogCommentLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 3,
  message: { error: 'Too many comments submitted from this IP. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);
app.use('/api/stem/register', authLimiter);
app.use('/api/nkwa/webhook', authLimiter);

app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(clerkMiddleware());
app.use(cors({
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    if (!origin) return callback(null, true);
    const allowedOrigins = [
      CORS_ORIGIN,
      'https://kcwebsite-rho.vercel.app',
      'http://localhost:5173',
      'http://localhost:3000',
      'https://localhost:5173',
      'https://localhost:3000',
    ];
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
}));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

const STEM_GRADES = ['Form 1', 'Form 2', 'Form 3', 'Form 4', 'Form 5', 'Lower Sixth', 'Upper Sixth'] as const;
const STEM_PAYMENT_METHODS = ['mtn', 'orange'] as const;
type StemPaymentMethod = typeof STEM_PAYMENT_METHODS[number];
type StemGrade = typeof STEM_GRADES[number];

function normalizeCameroonPhone(raw: unknown): string | null {
  const digits = String(raw || '').replace(/[^\d+]/g, '').trim();
  if (!digits) return null;
  if (/^\+237[6-9]\d{8}$/.test(digits)) return digits;
  if (/^237[6-9]\d{8}$/.test(digits)) return `+${digits}`;
  if (/^[6-9]\d{8}$/.test(digits)) return `+237${digits}`;
  return null;
}

function splitFullName(fullName: string): { firstName: string; lastName: string } | null {
  const parts = fullName.split(/\s+/).filter(Boolean);
  if (parts.length < 2) return null;
  return {
    firstName: parts[0],
    lastName: parts.slice(1).join(' '),
  };
}

function normalizeStemRegistrationPayload(payload: any) {
  const fullName = String(payload?.fullName || '').trim();
  const nameParts = fullName ? splitFullName(fullName) : null;
  const firstName = String(payload?.firstName || nameParts?.firstName || '').trim();
  const lastName = String(payload?.lastName || nameParts?.lastName || '').trim();
  const email = String(payload?.email || '').toLowerCase().trim();
  const studentPhone = normalizeCameroonPhone(payload?.phone);
  const payerPhone = normalizeCameroonPhone(payload?.payerPhone || payload?.phone);
  const guardianPhone = normalizeCameroonPhone(payload?.guardianPhone);
  const school = String(payload?.school || '').trim();
  const grade = String(payload?.grade || payload?.schoolClass || '').trim();
  const paymentMethod = String(payload?.paymentMethod || '').trim().toLowerCase() as StemPaymentMethod;
  const gender = String(payload?.gender || '').trim().toLowerCase();
  const level = String(payload?.level || '').trim().toLowerCase();
  const dobISO = String(payload?.dobISO || '').trim();
  const region = String(payload?.region || '').trim();
  const examLocation = String(payload?.examLocation || '').trim();
  const expectations = String(payload?.expectations || payload?.motivation || '').trim();
  const subjects = Array.isArray(payload?.subjects) ? payload.subjects.map((item: unknown) => String(item).trim()).filter(Boolean) : [];

  if (!firstName || firstName.length < 2 || !/^[a-zA-Z\s'-]+$/.test(firstName)) return { error: 'First name must be at least 2 valid characters' } as const;
  if (!lastName || lastName.length < 2 || !/^[a-zA-Z\s'-]+$/.test(lastName)) return { error: 'Last name must be at least 2 valid characters' } as const;
  if (!validator.isEmail(email)) return { error: 'Please provide a valid email address' } as const;
  if (!studentPhone) return { error: 'Student phone number must be a valid Cameroonian number' } as const;
  if (!payerPhone) return { error: 'Payer phone number must be a valid Cameroonian number' } as const;
  if (guardianPhone === null && payload?.guardianPhone) return { error: 'Guardian phone number must be a valid Cameroonian number' } as const;
  if (!school || school.length < 2 || school.length > 100) return { error: 'School name must be between 2 and 100 characters' } as const;
  if (!(STEM_GRADES as readonly string[]).includes(grade)) return { error: 'Please select a valid grade level' } as const;
  if (!(STEM_PAYMENT_METHODS as readonly string[]).includes(paymentMethod)) return { error: 'Payment method must be either MTN or Orange' } as const;
  if (dobISO && Number.isNaN(new Date(dobISO).getTime())) return { error: 'Date of birth must be a valid ISO date' } as const;
  if (gender && !['male', 'female', 'other'].includes(gender)) return { error: 'Gender must be male, female, or other' } as const;
  if (level && !['olevel', 'alevel'].includes(level)) return { error: 'Level must be olevel or alevel' } as const;

  return {
    value: {
      firstName,
      lastName,
      email,
      phone: studentPhone,
      payerPhone,
      guardianPhone: guardianPhone || '',
      dobISO,
      gender,
      school,
      grade: grade as StemGrade,
      paymentMethod,
      schoolClass: String(payload?.schoolClass || grade).trim(),
      level,
      region,
      examLocation,
      expectations,
      subjects,
    },
  } as const;
}

const validateRegistration = [
  body('payload').custom((payload) => {
    const normalized = normalizeStemRegistrationPayload(payload);
    if ('error' in normalized) throw new Error(normalized.error);
    return true;
  }),
  body('amount').isInt({ min: 1000, max: 100000 }).withMessage('Amount must be between 1000 and 100000 FCFA'),
];

const SubscriberSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    index: true,
    lowercase: true,
    validate: { validator: (email: string) => validator.isEmail(email), message: 'Please provide a valid email address' },
  },
  created_at: { type: Date, default: Date.now },
});
const Subscriber = model('Subscriber', SubscriberSchema);

const RegistrationSchema = new Schema({
  reference: { type: String, required: true, unique: true, index: true },
  amount: { type: Number, required: true, min: 1000, max: 100000 },
  payload: {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, validate: { validator: (email: string) => validator.isEmail(email), message: 'Please provide a valid email address' } },
    phone: { type: String, required: true, validate: { validator: (phone: string) => /^\+237[6-9]\d{8}$/.test(phone), message: 'Phone number must be in Cameroon format: +237XXXXXXXXX' } },
    payerPhone: { type: String, required: true, validate: { validator: (phone: string) => /^\+237[6-9]\d{8}$/.test(phone), message: 'Payer phone number must be in Cameroon format: +237XXXXXXXXX' } },
    guardianPhone: { type: String },
    dobISO: { type: String },
    gender: { type: String },
    school: { type: String, required: true },
    grade: { type: String, required: true },
    paymentMethod: { type: String, required: true, enum: ['mtn', 'orange'] },
    schoolClass: { type: String },
    level: { type: String },
    region: { type: String },
    examLocation: { type: String },
    expectations: { type: String },
    subjects: { type: [String], default: [] },
  },
  status: { type: String, enum: ['pending', 'processing', 'success', 'failed', 'cancelled'], default: 'pending' },
  nkwaTransactionId: { type: String },
  paymentDetails: { type: Object },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date },
  completed_at: { type: Date },
});
const Registration = model('Registration', RegistrationSchema);

const TimelineSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String },
  date_iso: { type: Date, required: true, index: true },
  tag: { type: String },
  imageUrl: { type: String },
  linkUrl: { type: String },
});
const TimelineItem = model('TimelineItem', TimelineSchema);

const BlogLikeSchema = new Schema({
  postId: { type: String, required: true, index: true },
  browserUuid: { type: String, required: true, index: true },
  created_at: { type: Date, default: Date.now },
});
BlogLikeSchema.index({ postId: 1, browserUuid: 1 }, { unique: true });
const BlogLike = model('BlogLike', BlogLikeSchema);

const BlogCommentSchema = new Schema({
  postId: { type: String, required: true, index: true },
  userId: { type: String, required: true },
  author: {
    type: String,
    required: true,
    maxlength: 50,
    validate: { validator: (name: string) => /^[a-zA-Z\s'-]+$/.test(name), message: 'Author name can only contain letters, spaces, hyphens, and apostrophes' },
  },
  content: {
    type: String,
    required: true,
    maxlength: 1000,
    validate: { validator: (content: string) => content.trim().length > 0, message: 'Comment content cannot be empty' },
  },
  parentId: { type: String, default: null },
  guestEmail: { type: String, default: '' },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  browserUuid: { type: String, default: '' },
  likes: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date },
});
const BlogComment = model('BlogComment', BlogCommentSchema);

const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true, lowercase: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
  isEmailVerified: { type: Boolean, default: false },
  lastLoginAt: { type: Date },
  created_at: { type: Date, default: Date.now },
});
const User = model('User', UserSchema);

const PendingUserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true, lowercase: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
  verificationCodeHash: { type: String, required: true },
  verificationCodeExpiresAt: { type: Date, required: true, index: true },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});
const PendingUser = model('PendingUser', PendingUserSchema);

const AuthTokenSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['reset_password'], required: true, index: true },
  tokenHash: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true, index: true },
  usedAt: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
});
const AuthToken = model('AuthToken', AuthTokenSchema);

const GspApplicationSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  data: { type: Schema.Types.Mixed, default: {} },
  sectionState: { type: Schema.Types.Mixed, default: {} },
  progressPct: { type: Number, default: 0 },
  status: { type: String, enum: ['draft', 'submitted'], default: 'draft' },
  reference: { type: String, index: true, unique: true, sparse: true },
  submittedAt: { type: Date, default: null },
  decisionStatus: { type: String, enum: ['pending', 'accepted', 'waitlisted', 'not_admitted'], default: 'pending' },
  decisionUpdatedAt: { type: Date, default: null },
  adminNotes: { type: String, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});
const GspApplication = model('GspApplication', GspApplicationSchema);

const DecisionReleaseSchema = new Schema({
  key: { type: String, required: true, unique: true, index: true },
  isReleased: { type: Boolean, default: false },
  releasedAt: { type: Date, default: null },
  updatedAt: { type: Date, default: Date.now },
});
const DecisionRelease = model('DecisionRelease', DecisionReleaseSchema);

const EmailLogSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  email: { type: String, required: true, index: true },
  type: { type: String, required: true, index: true },
  status: { type: String, enum: ['queued', 'sent', 'failed'], default: 'queued' },
  error: { type: String },
  meta: { type: Schema.Types.Mixed },
  created_at: { type: Date, default: Date.now },
});
const EmailLog = model('EmailLog', EmailLogSchema);

const EmailTemplateSchema = new Schema({
  type: { type: String, required: true, unique: true, index: true },
  subject: { type: String, required: true },
  html: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
});
const EmailTemplate = model('EmailTemplate', EmailTemplateSchema);

const BlogPostSchema = new Schema({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true, index: true },
  excerpt: { type: String, default: '' },
  content: { type: String, required: true },
  coverImageUrl: { type: String, default: '' },
  category: { type: String, default: '' },
  tags: { type: [String], default: [] },
  status: { type: String, enum: ['draft', 'published'], default: 'draft' },
  authorId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  authorName: { type: String, required: true },
  publishedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  viewCount: { type: Number, default: 0 },
});
const BlogPost = model('BlogPost', BlogPostSchema);

function makeTokenHash(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}
function passwordHash(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const incoming = scryptSync(password, salt, 64);
  const original = Buffer.from(hash, 'hex');
  if (incoming.length !== original.length) return false;
  return timingSafeEqual(incoming, original);
}
function b64url(data: Buffer | string): string {
  return Buffer.from(data).toString('base64url');
}
function createSessionToken(payload: { userId: string; role: 'student' | 'admin'; email: string }) {
  const body = b64url(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  const sig = createHmac('sha256', APP_AUTH_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifySessionToken(token: string): null | { userId: string; role: 'student' | 'admin'; email: string } {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = createHmac('sha256', APP_AUTH_SECRET).update(body).digest('base64url');
  if (sig !== expected) return null;
  const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!parsed.exp || parsed.exp < Date.now()) return null;
  return { userId: parsed.userId, role: parsed.role, email: parsed.email };
}
function getBearerToken(req: Request): string | null {
  const raw = req.headers.authorization;
  if (!raw || !raw.startsWith('Bearer ')) return null;
  return raw.slice(7).trim();
}
function isDatabaseConnected(): boolean {
  return mongoose.connection.readyState === 1;
}
function requireDatabase(_req: Request, res: Response, next: NextFunction) {
  if (!isDatabaseConnected()) {
    return res.status(503).json({ error: 'Database unavailable', message: 'Configure a valid MongoDB connection to use this endpoint.' });
  }
  next();
}
function countWords(value: string): number {
  return value.trim().split(/\s+/).filter(Boolean).length;
}
function createVerificationCode(): string {
  return String(randomInt(100000, 1000000));
}
function applyTemplateVars(value: string, templateVars?: Record<string, string>) {
  return value
    .replace(/\{\{name\}\}/g, templateVars?.name ?? '')
    .replace(/\{\{verificationCode\}\}/g, templateVars?.verificationCode ?? '')
    .replace(/\{\{resetLink\}\}/g, templateVars?.resetLink ?? '')
    .replace(/\{\{reference\}\}/g, templateVars?.reference ?? '');
}
function sanitizeApplicationForApplicant(application: any) {
  if (!application) return application;
  const plain = typeof application.toObject === 'function' ? application.toObject() : { ...application };
  delete plain.adminNotes;
  return plain;
}
function escapeCsv(value: unknown): string {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}
function slugifyBlogTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}
async function ensureUniqueBlogSlug(baseSlug: string, excludeId?: string): Promise<string> {
  const normalizedBase = slugifyBlogTitle(baseSlug) || `post-${Date.now()}`;
  let candidate = normalizedBase;
  let suffix = 2;
  while (true) {
    const existing = await BlogPost.findOne({
      slug: candidate,
      ...(excludeId ? { _id: { $ne: excludeId } } : {}),
    }).select('_id');
    if (!existing) return candidate;
    candidate = `${normalizedBase}-${suffix}`;
    suffix += 1;
  }
}
function buildAdminApplicationFilter(query: string, status: string, decisionStatus: string, grade: string, userIds: string[]) {
  const baseFilter: Record<string, any> = {};
  if (status) baseFilter.status = status;
  if (decisionStatus) baseFilter.decisionStatus = decisionStatus;
  if (grade) baseFilter['data.currentClass'] = grade;
  if (userIds.length > 0) baseFilter.userId = { $in: userIds };
  if (query && userIds.length === 0) baseFilter.userId = { $in: [] };
  return baseFilter;
}
async function resolveApplicationUserIds(query: string): Promise<string[]> {
  if (!query) return [];
  const users = await User.find({
    $or: [
      { email: { $regex: query, $options: 'i' } },
      { name: { $regex: query, $options: 'i' } },
    ],
  }).select('_id');
  return users.map((user: any) => String(user._id));
}
async function resolveBroadcastRecipients(recipients: string): Promise<Array<{ email: string; userId: string }>> {
  if (recipients === 'all_users') {
    const users = await User.find({}).select('_id email').lean();
    return users.map((user: any) => ({ email: user.email, userId: String(user._id) }));
  }

  const appFilter: Record<string, any> = { status: 'submitted' };
  if (recipients === 'accepted' || recipients === 'waitlisted' || recipients === 'not_admitted') {
    appFilter.decisionStatus = recipients;
  } else if (recipients === 'pending_decision') {
    appFilter.decisionStatus = 'pending';
  } else if (recipients !== 'submitted_applicants') {
    return [];
  }

  const applications = await GspApplication.find(appFilter).select('userId').lean();
  const userIds = applications.map((application: any) => application.userId);
  const users = await User.find({ _id: { $in: userIds } }).select('_id email').lean();
  return users.map((user: any) => ({ email: user.email, userId: String(user._id) }));
}
async function sendEmail(
  to: string,
  subject: string,
  html: string,
  type: string,
  userId?: string,
  meta?: any,
  templateVars?: Record<string, string>,
) {
  const log = await EmailLog.create({ userId, email: to, type, status: 'queued', meta });
  if (!process.env.RESEND_API_KEY) {
    await EmailLog.updateOne({ _id: log._id }, { status: 'failed', error: 'Resend API key not configured' });
    return false;
  }
  try {
    const template = await EmailTemplate.findOne({ type }).lean();
    const resolvedSubject = applyTemplateVars(template?.subject || subject, templateVars);
    const resolvedHtml = applyTemplateVars(template?.html || html, templateVars);
    await resend.emails.send({
      from: EMAIL_FROM,
      to,
      subject: resolvedSubject,
      html: resolvedHtml,
    });
    await EmailLog.updateOne({ _id: log._id }, { status: 'sent' });
    return true;
  } catch (error: any) {
    await EmailLog.updateOne({ _id: log._id }, { status: 'failed', error: String(error?.message || error) });
    return false;
  }
}
async function seedEmailTemplates() {
  const templates = [
    {
      type: 'auth_verification_code',
      subject: 'Your KC GSP verification code',
      html: '<p>Hello {{name}},</p><p>Use this verification code to complete your Knowledge Center Global Scholars Programme account setup:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">{{verificationCode}}</p><p>This code expires in 10 minutes.</p>',
    },
    {
      type: 'auth_verification_code_resend',
      subject: 'Your KC GSP verification code',
      html: '<p>Hello {{name}},</p><p>Use this verification code to complete your Knowledge Center Global Scholars Programme account setup:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">{{verificationCode}}</p><p>This code expires in 10 minutes.</p>',
    },
    {
      type: 'auth_reset_password',
      subject: 'Reset your KC GSP password',
      html: '<p>Hello {{name}},</p><p>Use this link to reset your password.</p><p><a href="{{resetLink}}">Reset password</a></p><p>This link expires in 30 minutes.</p>',
    },
    {
      type: 'gsp_submission_confirmation',
      subject: 'KC GSP Application Submitted',
      html: '<p>Hello {{name}},</p><p>Your KC Global Scholars Programme application has been submitted successfully.</p><p><strong>Reference:</strong> {{reference}}</p><p>You can now track your status from your dashboard.</p>',
    },
    {
      type: 'gsp_decision_release',
      subject: 'KC GSP Decision Update',
      html: '<p>Hello {{name}},</p><p>Your KC Global Scholars Programme decision is now available in your portal dashboard.</p><p>Please sign in to view your decision.</p>',
    },
  ];

  await Promise.all(templates.map((template) => EmailTemplate.updateOne(
    { type: template.type },
    { $setOnInsert: template },
    { upsert: true },
  )));
}
async function ensureDecisionConfig() {
  const key = 'gsp-2026';
  const existing = await DecisionRelease.findOne({ key });
  if (existing) return existing;
  return DecisionRelease.create({ key, isReleased: false, releasedAt: null, updatedAt: new Date() });
}
function computeProgress(sectionState: Record<string, boolean>) {
  const sections = ['section1', 'section2', 'section3', 'section4', 'section5', 'section6', 'section8', 'section9', 'section10', 'review'];
  const done = sections.filter((s) => sectionState?.[s]).length;
  return Math.round((done / sections.length) * 100);
}
function getValidationErrorsForSubmit(data: any) {
  const errors: string[] = [];
  const isEmpty = (v: any) => v === null || v === undefined || String(v).trim() === '';
  const requireField = (value: any, label: string) => {
    if (isEmpty(value)) errors.push(`${label} is required`);
  };
  const requireWordMax = (value: any, max: number, label: string) => {
    if (isEmpty(value)) return;
    if (countWords(String(value)) > max) errors.push(`${label} must be ${max} words or less`);
  };
  const requireWordRange = (value: any, min: number, max: number, label: string) => {
    const words = countWords(String(value || ''));
    if (words < min || words > max) errors.push(`${label} must be between ${min} and ${max} words`);
  };

  requireField(data?.firstName, 'First name');
  requireField(data?.lastName, 'Last name');
  requireField(data?.dob, 'Date of birth');
  requireField(data?.phone, 'Phone number');
  requireField(data?.email, 'Email');
  requireField(data?.gender, 'Gender');
  requireField(data?.nationality, 'Nationality');
  requireField(data?.city, 'City');
  requireField(data?.region, 'Region');
  requireField(data?.householdSize, 'Household size');
  requireField(data?.primaryGuardianOccupation, 'Primary guardian occupation');
  requireField(data?.highestFamilyEducation, 'Highest family education');
  requireField(data?.familyStudiedAbroad, 'Family studied abroad');
  if (data?.familyStudiedAbroad === 'yes') requireWordMax(data?.familyAbroadDetails, 150, 'Family abroad details');
  requireField(data?.schoolName, 'School name');
  requireField(data?.schoolCity, 'School city');
  requireField(data?.schoolRegion, 'School region');
  requireField(data?.currentClass, 'Current form/class');
  if (data?.currentClass === 'lower_sixth') requireField(data?.lowerSixthPathwayChoice, 'Lower Sixth pathway choice');
  if (!Array.isArray(data?.topSubjects) || data.topSubjects.length !== 5) errors.push('You must provide exactly 5 strongest subjects');
  else {
    data.topSubjects.forEach((subject: any, idx: number) => {
      requireField(subject?.name, `Subject ${idx + 1} name`);
      requireField(subject?.score, `Subject ${idx + 1} score`);
      requireField(subject?.examTerm, `Subject ${idx + 1} exam/term`);
    });
  }
  requireField(data?.intendedFieldWhy, 'Intended university field essay');
  requireWordMax(data?.intendedFieldWhy, 150, 'Intended university field essay');
  requireField(data?.communityEssay, 'Short answer response');
  requireWordRange(data?.communityEssay, 75, 225, 'Short answer response');
  if (!Array.isArray(data?.activities) || data.activities.length < 1 || data.activities.length > 3) errors.push('Provide between 1 and 3 activities');
  else {
    data.activities.forEach((activity: any, idx: number) => {
      requireField(activity?.title, `Activity ${idx + 1} title`);
      requireField(activity?.roleDescription, `Activity ${idx + 1} role description`);
      requireField(activity?.duration, `Activity ${idx + 1} duration`);
      requireField(activity?.hoursPerWeek, `Activity ${idx + 1} hours per week`);
      requireField(activity?.weeksPerYear, `Activity ${idx + 1} weeks per year`);
      requireField(activity?.isStillDoing, `Activity ${idx + 1} current status`);
      if (activity?.isStillDoing === 'no') requireField(activity?.stoppedIn, `Activity ${idx + 1} stop date`);
    });
  }
  requireField(data?.housingOption, 'Housing option');
  if (data?.housingOption === 'B') {
    requireField(data?.housingContactRelation, 'Housing contact relationship');
    requireField(data?.housingContactAware, 'Housing contact awareness');
  }
  if (data?.housingOption === 'C') {
    requireField(data?.canCoverHousingCost, 'Housing cost ability');
  }
  requireField(data?.participationConstraint, 'Participation constraints');
  if (data?.participationConstraint === 'yes') requireWordMax(data?.participationConstraintExplain, 200, 'Participation constraints explanation');
  requireField(data?.monthlyIncomeRange, 'Monthly household income');
  requireField(data?.worksToSupportFamily, 'Work support question');
  if (data?.worksToSupportFamily === 'yes') requireWordMax(data?.workSupportDetails, 100, 'Work support details');
  requireField(data?.costChallenge, 'Programme cost challenge response');
  requireField(data?.applyingScholarship, 'Scholarship intent');
  if (data?.applyingScholarship === 'yes') requireField(data?.scholarshipEssay, 'Scholarship essay');
  requireField(data?.documents?.reportCard?.url, 'Report card document');
  requireField(data?.documents?.olSlip?.url, 'O-Level slip document');
  if (data?.declarationConfirmed !== true) errors.push('Declaration confirmation is required');
  return errors;
}

type AuthUser = { userId: string; role: 'student' | 'admin'; email: string };
async function requireAuth(req: Request, res: Response): Promise<AuthUser | null> {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return null;
  }
  const decoded = verifySessionToken(token);
  if (!decoded) {
    res.status(401).json({ error: 'Invalid session' });
    return null;
  }
  return decoded;
}
async function requireAdmin(req: Request, res: Response): Promise<AuthUser | null> {
  const auth = await requireAuth(req, res);
  if (!auth) return null;
  if (auth.role !== 'admin') {
    res.status(403).json({ error: 'Admin access required' });
    return null;
  }
  return auth;
}

app.get('/health', async (_req: Request, res: Response) => {
  const healthCheck = {
    ok: true,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'disconnected',
    services: { mongodb: false, nkwa: false },
  };
  try {
    if (mongoose.connection.readyState === 1 && mongoose.connection.db) {
      await mongoose.connection.db.admin().ping();
      healthCheck.database = 'connected';
      healthCheck.services.mongodb = true;
    } else {
      healthCheck.ok = false;
      healthCheck.database = 'disconnected';
    }
  } catch (_error) {
    healthCheck.ok = false;
    healthCheck.database = 'error';
  }
  if (NKWA_API_KEY) {
    try {
      await axios.get(`${NKWA_BASE_URL}/health`, { headers: { Authorization: `Bearer ${NKWA_API_KEY}` }, timeout: 5000 });
      healthCheck.services.nkwa = true;
    } catch (_error) {
      healthCheck.services.nkwa = false;
    }
  }
  res.status(healthCheck.ok ? 200 : 503).json(healthCheck);
});

app.use('/api/newsletter', requireDatabase);
app.use('/api/auth', requireDatabase);
app.use('/api/gsp', requireDatabase);
app.use('/api/admin', requireDatabase);
app.use('/api/stem/register', requireDatabase);
app.use('/api/nkwa/webhook', requireDatabase);
app.use('/api/timeline', requireDatabase);
app.use('/api/blog', requireDatabase);

app.post('/api/newsletter',
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
  async (req: Request, res: Response) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });
      const { email } = req.body;
      if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Invalid email address' });
      const normalizedEmail = email.toLowerCase().trim();
      const existingSubscriber = await Subscriber.findOne({ email: normalizedEmail });
      if (existingSubscriber) return res.status(409).json({ error: 'Email already subscribed' });
      await Subscriber.create({ email: normalizedEmail, created_at: new Date() });
      return res.json({ success: true, message: 'Successfully subscribed to newsletter' });
    } catch (error) {
      console.error('Newsletter subscription error:', error);
      return res.status(500).json({ error: 'Internal server error', message: 'Failed to subscribe to newsletter' });
    }
  },
);

app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').toLowerCase().trim();
    const password = String(req.body?.password || '');
    if (!name || name.length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters' });
    if (!validator.isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already exists' });

    const role = ADMIN_EMAIL_ALLOWLIST.includes(email) ? 'admin' : 'student';
    const verificationCode = createVerificationCode();
    const verificationCodeHash = makeTokenHash(`${email}:${verificationCode}`);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 10);

    await PendingUser.findOneAndUpdate(
      { email },
      {
        $set: {
          name: validator.escape(name),
          email,
          passwordHash: passwordHash(password),
          role,
          verificationCodeHash,
          verificationCodeExpiresAt: expiresAt,
          updated_at: new Date(),
        },
        $setOnInsert: {
          created_at: new Date(),
        },
      },
      { upsert: true, new: true },
    );

    const responseBody = {
      success: true,
      requiresVerification: true,
      email,
      message: 'Verification code sent. Your account will be created after verification.',
      ...(process.env.NODE_ENV !== 'production' ? { debugVerificationCode: verificationCode } : {}),
    };
    res.status(201).json(responseBody);
    sendEmail(
      email,
      'Your KC GSP verification code',
      `<p>Hello ${validator.escape(name)},</p><p>Use this verification code to complete your Knowledge Center Global Scholars Programme account setup:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${verificationCode}</p><p>This code expires in 10 minutes.</p>`,
      'auth_verification_code',
      undefined,
      { email },
      { name: validator.escape(name), verificationCode },
    ).catch(console.error);
    return;
  } catch (error) {
    console.error('register error', error);
    return res.status(500).json({ error: 'Failed to start account verification' });
  }
});

app.post('/api/auth/verify-email', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').toLowerCase().trim();
    const code = String(req.body?.code || '').trim();
    if (!validator.isEmail(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Valid email and 6-digit code are required' });
    }

    const pendingUser = await PendingUser.findOne({ email });
    if (!pendingUser) return res.status(404).json({ error: 'No pending verification found for this email' });
    if (pendingUser.verificationCodeExpiresAt <= new Date()) {
      return res.status(400).json({ error: 'Verification code has expired. Request a new code.' });
    }
    if (pendingUser.verificationCodeHash !== makeTokenHash(`${email}:${code}`)) {
      return res.status(400).json({ error: 'Verification code is invalid' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      await PendingUser.deleteOne({ _id: pendingUser._id });
      return res.status(409).json({ error: 'Email already exists' });
    }

    const user = await User.create({
      name: pendingUser.name,
      email: pendingUser.email,
      passwordHash: pendingUser.passwordHash,
      role: pendingUser.role,
      isEmailVerified: true,
      lastLoginAt: new Date(),
      created_at: new Date(),
    });
    await PendingUser.deleteOne({ _id: pendingUser._id });

    const token = createSessionToken({ userId: String(user._id), role: user.role as 'student' | 'admin', email: user.email });
    return res.json({
      success: true,
      message: 'Email verified successfully',
      token,
      user: {
        id: String(user._id),
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error('verify email error', error);
    return res.status(500).json({ error: 'Failed to verify email' });
  }
});

app.post('/api/auth/resend-verification-code', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').toLowerCase().trim();
    if (!validator.isEmail(email)) return res.status(400).json({ error: 'Valid email required' });

    const pendingUser = await PendingUser.findOne({ email });
    if (!pendingUser) return res.status(404).json({ error: 'No pending verification found for this email' });

    const verificationCode = createVerificationCode();
    const verificationCodeHash = makeTokenHash(`${email}:${verificationCode}`);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 10);

    await PendingUser.updateOne(
      { _id: pendingUser._id },
      {
        verificationCodeHash,
        verificationCodeExpiresAt: expiresAt,
        updated_at: new Date(),
      },
    );

    const responseBody = {
      success: true,
      message: 'A new verification code has been sent.',
      ...(process.env.NODE_ENV !== 'production' ? { debugVerificationCode: verificationCode } : {}),
    };
    res.json(responseBody);
    sendEmail(
      pendingUser.email,
      'Your KC GSP verification code',
      `<p>Hello ${validator.escape(pendingUser.name)},</p><p>Use this verification code to complete your Knowledge Center Global Scholars Programme account setup:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${verificationCode}</p><p>This code expires in 10 minutes.</p>`,
      'auth_verification_code_resend',
      undefined,
      { email: pendingUser.email },
      { name: validator.escape(pendingUser.name), verificationCode },
    ).catch(console.error);
    return;
  } catch (error) {
    console.error('resend verification code error', error);
    return res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').toLowerCase().trim();
    const password = String(req.body?.password || '');
    if (!validator.isEmail(email) || !password) return res.status(400).json({ error: 'Email and password are required' });
    const user = await User.findOne({ email });
    if (!user) {
      const pendingUser = await PendingUser.findOne({ email });
      if (pendingUser) {
        return res.status(403).json({ error: 'Finish email verification to create your account and sign in' });
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.isEmailVerified) return res.status(403).json({ error: 'Please verify your email before login' });
    await User.updateOne({ _id: user._id }, { lastLoginAt: new Date() });
    const token = createSessionToken({ userId: String(user._id), role: user.role as any, email: user.email });
    return res.json({
      token,
      user: {
        id: String(user._id),
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error('login error', error);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/auth/logout', async (_req: Request, res: Response) => {
  return res.json({ success: true });
});

app.post('/api/auth/forgot-password', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').toLowerCase().trim();
    if (!validator.isEmail(email)) return res.json({ success: true });
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: true });
    const rawToken = `${randomUUID()}${randomBytes(12).toString('hex')}`;
    await AuthToken.create({
      userId: user._id,
      type: 'reset_password',
      tokenHash: makeTokenHash(rawToken),
      expiresAt: new Date(Date.now() + 1000 * 60 * 30),
      created_at: new Date(),
    });
    const resetLink = `${APP_BASE_URL}/gsp?resetToken=${encodeURIComponent(rawToken)}`;
    const responseBody = {
      success: true,
      ...(process.env.NODE_ENV !== 'production' ? { debugResetToken: rawToken } : {}),
    };
    res.json(responseBody);
    sendEmail(
      user.email,
      'Reset your KC GSP password',
      `<p>Hello ${validator.escape(user.name)},</p><p>Use this link to reset your password.</p><p><a href="${resetLink}">Reset password</a></p><p>This link expires in 30 minutes.</p>`,
      'auth_reset_password',
      String(user._id),
      { resetLink },
      { name: validator.escape(user.name), resetLink },
    ).catch(console.error);
    return;
  } catch (error) {
    console.error('forgot password error', error);
    return res.status(500).json({ error: 'Failed to request password reset' });
  }
});

app.post('/api/auth/reset-password', async (req: Request, res: Response) => {
  try {
    const token = String(req.body?.token || '');
    const newPassword = String(req.body?.newPassword || '');
    if (!token || newPassword.length < 8) return res.status(400).json({ error: 'Token and valid password are required' });
    const tokenDoc = await AuthToken.findOne({
      tokenHash: makeTokenHash(token),
      type: 'reset_password',
      usedAt: null,
      expiresAt: { $gt: new Date() },
    });
    if (!tokenDoc) return res.status(400).json({ error: 'Token is invalid or expired' });
    await User.updateOne({ _id: tokenDoc.userId }, { passwordHash: passwordHash(newPassword) });
    await AuthToken.updateOne({ _id: tokenDoc._id }, { usedAt: new Date() });
    return res.json({ success: true });
  } catch (error) {
    console.error('reset password error', error);
    return res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/auth/me', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const user = await User.findById(auth.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({
    user: {
      id: String(user._id),
      name: user.name,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      lastLoginAt: user.lastLoginAt,
    },
  });
});

app.get('/api/clerk-auth/me', async (req: Request, res: Response) => {
  try {
    const { userId: clerkUserId } = getAuth(req);
    if (!clerkUserId) return res.status(401).json({ error: 'Authentication required' });

    const clerkUser = await clerkClient.users.getUser(clerkUserId);
    const primaryEmailAddress = clerkUser.emailAddresses.find((item) => item.id === clerkUser.primaryEmailAddressId)
      || clerkUser.emailAddresses[0];
    const email = String(primaryEmailAddress?.emailAddress || '').toLowerCase().trim();
    if (!validator.isEmail(email)) return res.status(400).json({ error: 'Clerk user does not have a valid email address' });

    let user = await User.findOne({ email });
    if (!user) {
      const firstName = String(clerkUser.firstName || '').trim();
      const lastName = String(clerkUser.lastName || '').trim();
      const fullName = `${firstName} ${lastName}`.trim() || email.split('@')[0];
      user = await User.create({
        name: fullName,
        email,
        passwordHash: '',
        isEmailVerified: true,
        role: ADMIN_EMAIL_ALLOWLIST.includes(email) ? 'admin' : 'student',
        lastLoginAt: new Date(),
        created_at: new Date(),
      });
    } else {
      await User.updateOne({ _id: user._id }, { lastLoginAt: new Date(), isEmailVerified: true });
      user = await User.findById(user._id);
    }

    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = createSessionToken({ userId: String(user._id), role: user.role as 'student' | 'admin', email: user.email });
    return res.json({
      token,
      user: {
        id: String(user._id),
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error('clerk auth bridge error', error);
    return res.status(500).json({ error: 'Failed to authenticate Clerk user' });
  }
});

app.get('/api/gsp/application', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const user = await User.findById(auth.userId);
  const existing = await GspApplication.findOne({ userId: auth.userId });
  if (!existing) {
    return res.json({
      application: {
        data: { email: user?.email || '' },
        sectionState: {},
        progressPct: 0,
        status: 'draft',
        reference: null,
        decisionStatus: 'pending',
      },
    });
  }
  return res.json({ application: sanitizeApplicationForApplicant(existing) });
});

app.put('/api/gsp/application/draft', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const data = req.body?.data || {};
  const sectionState = req.body?.sectionState || {};
  const progressPct = computeProgress(sectionState);
  const existing = await GspApplication.findOne({ userId: auth.userId });
  if (existing?.status === 'submitted') return res.status(409).json({ error: 'Application already submitted and locked' });
  const updated = await GspApplication.findOneAndUpdate(
    { userId: auth.userId },
    {
      $set: { data, sectionState, progressPct, status: 'draft', updated_at: new Date() },
      $setOnInsert: { userId: auth.userId, created_at: new Date() },
    },
    { upsert: true, new: true },
  );
  return res.json({ success: true, application: updated });
});

app.post('/api/gsp/application/submit', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const data = req.body?.data || {};
  const sectionState = req.body?.sectionState || {};
  const errors = getValidationErrorsForSubmit(data);
  if (errors.length > 0) return res.status(400).json({ error: 'Validation failed', details: errors });

  const existing = await GspApplication.findOne({ userId: auth.userId });
  if (existing?.status === 'submitted') return res.status(409).json({ error: 'Application already submitted' });
  const reference = `KC-GSP-${new Date().getFullYear()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
  const progressPct = computeProgress({ ...sectionState, review: true });
  const saved = await GspApplication.findOneAndUpdate(
    { userId: auth.userId },
    {
      $set: {
        data,
        sectionState: { ...sectionState, review: true },
        progressPct,
        status: 'submitted',
        reference,
        submittedAt: new Date(),
        updated_at: new Date(),
      },
      $setOnInsert: { userId: auth.userId, created_at: new Date() },
    },
    { upsert: true, new: true },
  );
  const user = await User.findById(auth.userId);
  const responseBody = { success: true, reference, application: sanitizeApplicationForApplicant(saved) };
  res.json(responseBody);
  if (user) {
    sendEmail(
      user.email,
      'KC GSP Application Submitted',
      `<p>Hello ${validator.escape(user.name)},</p><p>Your KC Global Scholars Programme application has been submitted successfully.</p><p><strong>Reference:</strong> ${reference}</p><p>You can now track your status from your dashboard.</p>`,
      'gsp_submission_confirmation',
      String(user._id),
      { reference },
      { name: validator.escape(user.name), reference },
    ).catch(console.error);
  }
  return;
});

app.get('/api/gsp/application/decision', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const appRecord = await GspApplication.findOne({ userId: auth.userId });
  if (!appRecord) return res.status(404).json({ error: 'Application not found' });
  const release = await ensureDecisionConfig();
  if (!release.isReleased) return res.json({ released: false, decisionStatus: null });
  return res.json({
    released: true,
    decisionStatus: appRecord.decisionStatus,
    submittedAt: appRecord.submittedAt,
    reference: appRecord.reference,
    lowerSixthPathwayChoice: appRecord.data?.lowerSixthPathwayChoice || null,
  });
});

app.post('/api/gsp/uploads', async (req: Request, res: Response) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const fileName = String(req.body?.fileName || '');
  const mimeType = String(req.body?.mimeType || '');
  const dataUrl = String(req.body?.dataUrl || '');
  const allowed = ['application/pdf', 'image/jpeg', 'image/png'];
  if (!allowed.includes(mimeType)) return res.status(400).json({ error: 'Unsupported file type' });
  if (!dataUrl.startsWith('data:')) return res.status(400).json({ error: 'Invalid file payload' });
  const binaryLength = Buffer.from(dataUrl.split(',')[1] || '', 'base64').length;
  if (binaryLength > 10 * 1024 * 1024) return res.status(400).json({ error: 'File exceeds 10MB size limit' });
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    return res.status(500).json({ error: 'Cloudinary is not configured' });
  }
  try {
    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'knowledge-center/gsp';
    const signatureBase = `folder=${folder}&timestamp=${timestamp}${CLOUDINARY_API_SECRET}`;
    const signature = createHash('sha1').update(signatureBase).digest('hex');
    const formData = new FormData();
    formData.append('file', dataUrl);
    formData.append('api_key', CLOUDINARY_API_KEY);
    formData.append('timestamp', String(timestamp));
    formData.append('folder', folder);
    formData.append('signature', signature);
    const cloudResp = await fetch(`https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/auto/upload`, {
      method: 'POST',
      body: formData,
    });
    const cloudData = await cloudResp.json() as any;
    if (!cloudResp.ok) {
      return res.status(502).json({ error: 'Upload failed', details: cloudData?.error?.message || 'Unknown Cloudinary error' });
    }
    return res.json({
      url: cloudData.secure_url,
      publicId: cloudData.public_id,
      bytes: cloudData.bytes,
      format: cloudData.format,
      originalFilename: fileName,
    });
  } catch (error: any) {
    return res.status(500).json({ error: 'Upload failed', details: String(error?.message || error) });
  }
});

app.get('/api/admin/gsp/applications', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const query = String(req.query?.query || '').trim();
    const status = String(req.query?.status || '').trim();
    const decisionStatus = String(req.query?.decisionStatus || '').trim();
    const grade = String(req.query?.grade || '').trim();
    const matchedUserIds = await resolveApplicationUserIds(query);
    const baseFilter = buildAdminApplicationFilter(query, status, decisionStatus, grade, matchedUserIds);
    const applications = await GspApplication.find(baseFilter).sort({ submittedAt: -1, updated_at: -1 }).lean();
    const userIds = applications.map((application: any) => application.userId);
    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = new Map(users.map((user: any) => [String(user._id), user]));
    const merged = applications.map((application: any) => ({
      ...application,
      user: (() => {
        const user: any = userMap.get(String(application.userId));
        return user ? {
          id: String(user._id),
          name: user.name,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
        } : null;
      })(),
    }));
    return res.json({ applications: merged });
  } catch (error) {
    console.error('admin applications list error', error);
    return res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

app.get('/api/admin/gsp/applications/:id', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const appRecord = await GspApplication.findById(req.params.id).lean();
  if (!appRecord) return res.status(404).json({ error: 'Application not found' });
  const user = await User.findById((appRecord as any).userId).lean();
  return res.json({
    application: appRecord,
    user: user ? {
      id: String((user as any)._id),
      name: (user as any).name,
      email: (user as any).email,
      role: (user as any).role,
      isEmailVerified: (user as any).isEmailVerified,
      lastLoginAt: (user as any).lastLoginAt,
    } : null,
  });
});

app.patch('/api/admin/gsp/applications/:id/decision', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const decisionStatus = String(req.body?.decisionStatus || '');
  if (!['accepted', 'waitlisted', 'not_admitted', 'pending'].includes(decisionStatus)) {
    return res.status(400).json({ error: 'Invalid decision status' });
  }
  const updated = await GspApplication.findByIdAndUpdate(
    req.params.id,
    { decisionStatus, decisionUpdatedAt: new Date(), updated_at: new Date() },
    { new: true },
  );
  if (!updated) return res.status(404).json({ error: 'Application not found' });
  return res.json({ success: true, application: updated });
});

app.patch('/api/admin/gsp/release', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const isReleased = !!req.body?.isReleased;
  const current = await ensureDecisionConfig();
  const wasReleased = current.isReleased;
  const updated = await DecisionRelease.findOneAndUpdate(
    { key: 'gsp-2026' },
    { isReleased, releasedAt: isReleased ? new Date() : null, updatedAt: new Date() },
    { new: true },
  );
  if (!wasReleased && isReleased) {
    const apps = await GspApplication.find({ status: 'submitted', decisionStatus: { $in: ['accepted', 'waitlisted', 'not_admitted'] } }).lean();
    const userIds = apps.map((a: any) => a.userId);
    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = new Map(users.map((u: any) => [String(u._id), u]));
    for (const appRec of apps as any[]) {
      const user: any = userMap.get(String(appRec.userId));
      if (!user) continue;
      await sendEmail(
        user.email,
        'KC GSP Decision Update',
        `<p>Hello ${validator.escape(user.name)},</p><p>Your KC Global Scholars Programme decision is now available in your portal dashboard.</p><p>Please sign in to view your decision.</p>`,
        'gsp_decision_release',
        String(user._id),
        { applicationId: String(appRec._id), decisionStatus: appRec.decisionStatus },
        { name: validator.escape(user.name) },
      );
    }
  }
  return res.json({ success: true, release: updated });
});

app.get('/api/admin/gsp/release', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const release = await ensureDecisionConfig();
  return res.json({ release });
});

app.get('/api/admin/gsp/users', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const users = await User.find({}).sort({ created_at: -1 }).lean();
  return res.json({
    users: users.map((user: any) => ({
      id: String(user._id),
      name: user.name,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.created_at,
    })),
  });
});

app.get('/api/admin/stats', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const [totalUsers, submittedApplications, draftApplications, decisionBreakdownRaw, totalBlogPosts, pendingComments] = await Promise.all([
      User.countDocuments(),
      GspApplication.countDocuments({ status: 'submitted' }),
      GspApplication.countDocuments({ status: 'draft' }),
      GspApplication.aggregate([
        { $match: { status: 'submitted' } },
        { $group: { _id: '$decisionStatus', count: { $sum: 1 } } },
      ]),
      BlogPost.countDocuments(),
      BlogComment.countDocuments({ status: 'pending' }),
    ]);
    const decisionBreakdown = {
      pending: 0,
      accepted: 0,
      waitlisted: 0,
      not_admitted: 0,
    };
    for (const item of decisionBreakdownRaw) {
      if (item?._id && item._id in decisionBreakdown) {
        decisionBreakdown[item._id as keyof typeof decisionBreakdown] = item.count;
      }
    }
    return res.json({
      totalUsers,
      submittedApplications,
      draftApplications,
      decisionBreakdown,
      totalBlogPosts,
      pendingComments,
    });
  } catch (error) {
    console.error('admin stats error', error);
    return res.status(500).json({ error: 'Failed to fetch admin stats' });
  }
});

app.patch('/api/admin/gsp/applications/:id/notes', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const notes = String(req.body?.notes || '');
    const updated = await GspApplication.findByIdAndUpdate(
      req.params.id,
      { adminNotes: notes, updated_at: new Date() },
      { new: true },
    );
    if (!updated) return res.status(404).json({ error: 'Application not found' });
    return res.json({ success: true });
  } catch (error) {
    console.error('admin notes update error', error);
    return res.status(500).json({ error: 'Failed to update admin notes' });
  }
});

app.patch('/api/admin/gsp/applications/bulk-decision', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map((id: unknown) => String(id)).filter(Boolean) : [];
    const decisionStatus = String(req.body?.decisionStatus || '');
    if (ids.length === 0) return res.status(400).json({ error: 'ids must be a non-empty array' });
    if (!['pending', 'accepted', 'waitlisted', 'not_admitted'].includes(decisionStatus)) {
      return res.status(400).json({ error: 'Invalid decision status' });
    }
    const result = await GspApplication.updateMany(
      { _id: { $in: ids } },
      { decisionStatus, decisionUpdatedAt: new Date(), updated_at: new Date() },
    );
    return res.json({ updated: result.modifiedCount });
  } catch (error) {
    console.error('bulk decision error', error);
    return res.status(500).json({ error: 'Failed to update applications' });
  }
});

app.get('/api/admin/gsp/applications/export', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const query = String(req.query?.query || '').trim();
    const status = String(req.query?.status || '').trim();
    const decisionStatus = String(req.query?.decisionStatus || '').trim();
    const grade = String(req.query?.grade || '').trim();
    const matchedUserIds = await resolveApplicationUserIds(query);
    const baseFilter = buildAdminApplicationFilter(query, status, decisionStatus, grade, matchedUserIds);
    const applications = await GspApplication.find(baseFilter).sort({ submittedAt: -1, updated_at: -1 }).lean();
    const users = await User.find({ _id: { $in: applications.map((application: any) => application.userId) } }).lean();
    const userMap = new Map(users.map((user: any) => [String(user._id), user]));
    const headers = ['Reference', 'First Name', 'Last Name', 'Email', 'Phone', 'School', 'Grade', 'Region', 'Gender', 'Payment Method', 'Decision Status', 'Submitted At'];
    const rows = applications.map((application: any) => {
      const user: any = userMap.get(String(application.userId));
      return [
        application.reference,
        application.data?.firstName,
        application.data?.lastName,
        user?.email || application.data?.email,
        application.data?.phone,
        application.data?.schoolName,
        application.data?.currentClass,
        application.data?.region,
        application.data?.gender,
        application.data?.paymentMethod,
        application.decisionStatus,
        application.submittedAt ? new Date(application.submittedAt).toISOString() : '',
      ].map(escapeCsv).join(',');
    });
    const csv = [headers.map(escapeCsv).join(','), ...rows].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="kc-gsp-applications.csv"');
    return res.send(csv);
  } catch (error) {
    console.error('application export error', error);
    return res.status(500).json({ error: 'Failed to export applications' });
  }
});

app.get('/api/admin/email-templates', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const templates = await EmailTemplate.find({}).sort({ type: 1 }).lean();
    return res.json({ templates });
  } catch (error) {
    console.error('email templates list error', error);
    return res.status(500).json({ error: 'Failed to fetch email templates' });
  }
});

app.get('/api/admin/email-templates/:type', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const template = await EmailTemplate.findOne({ type: req.params.type }).lean();
    if (!template) return res.status(404).json({ error: 'Template not found' });
    return res.json({ template });
  } catch (error) {
    console.error('email template fetch error', error);
    return res.status(500).json({ error: 'Failed to fetch email template' });
  }
});

app.patch('/api/admin/email-templates/:type', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const updates: Record<string, any> = {
      updatedAt: new Date(),
      updatedBy: auth.userId,
    };
    if (typeof req.body?.subject === 'string') updates.subject = req.body.subject;
    if (typeof req.body?.html === 'string') updates.html = req.body.html;
    const template = await EmailTemplate.findOneAndUpdate(
      { type: req.params.type },
      updates,
      { new: true },
    );
    if (!template) return res.status(404).json({ error: 'Template not found' });
    return res.json({ template });
  } catch (error) {
    console.error('email template update error', error);
    return res.status(500).json({ error: 'Failed to update email template' });
  }
});

app.get('/api/admin/broadcast/count', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const recipients = String(req.query?.recipients || '');
    const resolvedRecipients = await resolveBroadcastRecipients(recipients);
    return res.json({ count: resolvedRecipients.length });
  } catch (error) {
    console.error('broadcast count error', error);
    return res.status(500).json({ error: 'Failed to count broadcast recipients' });
  }
});

app.post('/api/admin/broadcast', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const subject = String(req.body?.subject || '').trim();
    const html = String(req.body?.html || '').trim();
    const recipients = String(req.body?.recipients || '').trim();
    if (!subject || !html || !recipients) return res.status(400).json({ error: 'subject, html, and recipients are required' });
    const resolvedRecipients = await resolveBroadcastRecipients(recipients);
    res.json({ queued: resolvedRecipients.length });
    for (const recipient of resolvedRecipients) {
      sendEmail(recipient.email, subject, html, 'admin_broadcast', recipient.userId).catch(console.error);
    }
    return;
  } catch (error) {
    console.error('broadcast send error', error);
    return res.status(500).json({ error: 'Failed to queue broadcast email' });
  }
});

app.post('/api/stem/register', validateRegistration, async (req: Request, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    const { payload, amount } = req.body;
    if (!payload || !amount) return res.status(400).json({ error: 'Missing required fields', message: 'Payload and amount are required' });
    const normalized = normalizeStemRegistrationPayload(payload);
    if ('error' in normalized) return res.status(400).json({ error: normalized.error });
    if (!NKWA_API_KEY) return res.status(500).json({ error: 'Payment service unavailable', message: 'Payment integration not configured' });
    const sanitizedPayload = {
      firstName: validator.escape(normalized.value.firstName),
      lastName: validator.escape(normalized.value.lastName),
      email: normalized.value.email,
      phone: normalized.value.phone,
      payerPhone: normalized.value.payerPhone,
      guardianPhone: normalized.value.guardianPhone,
      dobISO: normalized.value.dobISO,
      gender: normalized.value.gender,
      school: validator.escape(normalized.value.school),
      grade: normalized.value.grade,
      paymentMethod: normalized.value.paymentMethod,
      schoolClass: normalized.value.schoolClass,
      level: normalized.value.level,
      region: normalized.value.region,
      examLocation: normalized.value.examLocation,
      expectations: normalized.value.expectations,
      subjects: normalized.value.subjects,
    };
    const reference = `KC-STEM-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    await Registration.create({ reference, amount, payload: sanitizedPayload, status: 'pending', created_at: new Date() });
    const nkwaPayload = {
      amount,
      payer: sanitizedPayload.payerPhone,
      operator: sanitizedPayload.paymentMethod,
      reference,
      currency: 'XAF',
      description: `KC STEM Registration - ${sanitizedPayload.firstName} ${sanitizedPayload.lastName}`,
      callback_url: `${BACKEND_PUBLIC_URL}/api/nkwa/webhook`,
    };
    try {
      const nkwaResponse = await axios.post(`${NKWA_BASE_URL}/nkwapay/collect`, nkwaPayload, {
        headers: { Authorization: `Bearer ${NKWA_API_KEY}`, 'Content-Type': 'application/json' },
        timeout: 10000,
      });
      await Registration.updateOne(
        { reference },
        { nkwaTransactionId: nkwaResponse.data?.transactionId, paymentDetails: nkwaResponse.data, status: 'processing', updated_at: new Date() },
      );
      return res.json({
        reference,
        status: 'processing',
        message: 'Payment request initiated successfully',
        nkwaResponse: process.env.NODE_ENV === 'development' ? nkwaResponse.data : undefined,
      });
    } catch (nkwaError: any) {
      await Registration.updateOne({ reference }, { status: 'failed', paymentDetails: nkwaError.response?.data, updated_at: new Date() });
      return res.status(502).json({ error: 'Payment service error', message: 'Failed to initiate payment. Please try again.', reference });
    }
  } catch (error) {
    console.error('STEM registration error:', error);
    return res.status(500).json({ error: 'Internal server error', message: 'Failed to process registration' });
  }
});

app.post('/api/nkwa/webhook', express.json({ type: '*/*' }), async (req: Request, res: Response) => {
  try {
    const event = req.body as any;
    const { reference, status, transactionId } = event || {};
    if (!reference) return res.status(400).json({ error: 'Missing reference' });
    const updateData: any = {
      status: status === 'success' ? 'success' : 'failed',
      nkwaTransactionId: transactionId,
      paymentDetails: event,
      updated_at: new Date(),
    };
    if (status === 'success') updateData.completed_at = new Date();
    const result = await Registration.updateOne({ reference }, updateData);
    if (result.matchedCount === 0) return res.status(404).json({ error: 'Registration not found' });
    return res.json({ received: true, reference, status: updateData.status });
  } catch (error) {
    console.error('Webhook processing error:', error);
    return res.status(500).json({ error: 'Webhook processing failed', message: 'Failed to process payment notification' });
  }
});

app.get('/api/timeline', async (_req: Request, res: Response) => {
  try {
    const timeline = await TimelineItem.find({}).sort({ date_iso: 1 }).lean();
    return res.json(timeline);
  } catch (_error) {
    return res.status(500).json({ error: 'Failed to fetch timeline' });
  }
});

app.post('/api/timeline', async (req: Request, res: Response) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  try {
    const payload = {
      title: String(req.body?.title || '').trim(),
      description: String(req.body?.description || '').trim(),
      date_iso: new Date(req.body?.dateISO || req.body?.date_iso),
      tag: String(req.body?.tag || '').trim(),
      imageUrl: String(req.body?.imageUrl || '').trim(),
      linkUrl: String(req.body?.linkUrl || '').trim(),
    };
    if (!payload.title || Number.isNaN(payload.date_iso.getTime())) return res.status(400).json({ error: 'Invalid timeline payload' });
    const item = await TimelineItem.create(payload);
    return res.status(201).json(item);
  } catch (_error) {
    return res.status(500).json({ error: 'Failed to add timeline item' });
  }
});

app.patch('/api/timeline/:id', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const payload = {
      title: String(req.body?.title || '').trim(),
      description: String(req.body?.description || '').trim(),
      date_iso: new Date(req.body?.dateISO || req.body?.date_iso),
      tag: String(req.body?.tag || '').trim(),
      imageUrl: String(req.body?.imageUrl || '').trim(),
      linkUrl: String(req.body?.linkUrl || '').trim(),
    };
    if (!payload.title || Number.isNaN(payload.date_iso.getTime())) return res.status(400).json({ error: 'Invalid timeline payload' });
    const item = await TimelineItem.findByIdAndUpdate(req.params.id, payload, { new: true });
    if (!item) return res.status(404).json({ error: 'Timeline item not found' });
    return res.json(item);
  } catch (error) {
    console.error('timeline update error', error);
    return res.status(500).json({ error: 'Failed to update timeline item' });
  }
});

app.delete('/api/timeline/:id', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const item = await TimelineItem.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'Timeline item not found' });
    return res.json({ deleted: true });
  } catch (error) {
    console.error('timeline delete error', error);
    return res.status(500).json({ error: 'Failed to delete timeline item' });
  }
});

app.get('/api/blog/posts', async (req: Request, res: Response) => {
  try {
    const category = String(req.query?.category || '').trim();
    const tag = String(req.query?.tag || '').trim();
    const page = Math.max(1, parseInt(String(req.query?.page || '1'), 10) || 1);
    const limit = Math.min(20, Math.max(1, parseInt(String(req.query?.limit || '10'), 10) || 10));
    const filter: Record<string, any> = { status: 'published' };
    if (category) filter.category = category;
    if (tag) filter.tags = tag;
    const [posts, total] = await Promise.all([
      BlogPost.find(filter).sort({ publishedAt: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      BlogPost.countDocuments(filter),
    ]);
    return res.json({
      posts: posts.map((post: any) => ({
        id: String(post._id),
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        content: post.content,
        coverImageUrl: post.coverImageUrl,
        category: post.category,
        tags: post.tags,
        status: post.status,
        authorName: post.authorName,
        publishedAt: post.publishedAt,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        viewCount: post.viewCount,
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('blog posts list error', error);
    return res.status(500).json({ error: 'Failed to fetch blog posts' });
  }
});

app.get('/api/blog/posts/:slug', async (req: Request, res: Response) => {
  try {
    const post = await BlogPost.findOneAndUpdate(
      { slug: req.params.slug, status: 'published' },
      { $inc: { viewCount: 1 } },
      { new: true },
    ).lean();
    if (!post) return res.status(404).json({ error: 'Blog post not found' });
    return res.json({
      post: {
        id: String(post._id),
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        content: post.content,
        coverImageUrl: post.coverImageUrl,
        category: post.category,
        tags: post.tags,
        status: post.status,
        authorName: post.authorName,
        publishedAt: post.publishedAt,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        viewCount: post.viewCount,
      },
    });
  } catch (error) {
    console.error('blog post fetch error', error);
    return res.status(500).json({ error: 'Failed to fetch blog post' });
  }
});

app.get('/api/blog/categories', async (_req: Request, res: Response) => {
  try {
    const categories = await BlogPost.distinct('category', { status: 'published' });
    return res.json({ categories: categories.filter(Boolean).sort() });
  } catch (error) {
    console.error('blog categories error', error);
    return res.status(500).json({ error: 'Failed to fetch blog categories' });
  }
});

app.get('/api/admin/blog/posts', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const posts = await BlogPost.find({}).sort({ createdAt: -1 }).lean();
    return res.json({
      posts: posts.map((post: any) => ({
        id: String(post._id),
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        content: post.content,
        coverImageUrl: post.coverImageUrl,
        category: post.category,
        tags: post.tags,
        status: post.status,
        authorId: String(post.authorId),
        authorName: post.authorName,
        publishedAt: post.publishedAt,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        viewCount: post.viewCount,
      })),
    });
  } catch (error) {
    console.error('admin blog list error', error);
    return res.status(500).json({ error: 'Failed to fetch blog posts' });
  }
});

app.post('/api/admin/blog/posts', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const admin = await User.findById(auth.userId);
    if (!admin) return res.status(404).json({ error: 'Admin user not found' });
    const title = String(req.body?.title || '').trim();
    const slugInput = String(req.body?.slug || title).trim();
    const content = String(req.body?.content || '').trim();
    if (!title || !content) return res.status(400).json({ error: 'title and content are required' });
    const slug = await ensureUniqueBlogSlug(slugInput);
    const post = await BlogPost.create({
      title,
      slug,
      excerpt: String(req.body?.excerpt || '').trim(),
      content,
      coverImageUrl: String(req.body?.coverImageUrl || '').trim(),
      category: String(req.body?.category || '').trim(),
      tags: Array.isArray(req.body?.tags) ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter(Boolean) : [],
      status: String(req.body?.status || 'draft') === 'published' ? 'published' : 'draft',
      authorId: admin._id,
      authorName: admin.name,
      publishedAt: String(req.body?.status || 'draft') === 'published' ? new Date() : null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    return res.status(201).json({ post });
  } catch (error) {
    console.error('admin blog create error', error);
    return res.status(500).json({ error: 'Failed to create blog post' });
  }
});

app.patch('/api/admin/blog/posts/:id', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const updates: Record<string, any> = { updatedAt: new Date() };
    const fieldKeys = ['title', 'excerpt', 'content', 'coverImageUrl', 'category', 'status'];
    for (const fieldKey of fieldKeys) {
      if (fieldKey in req.body) updates[fieldKey] = String(req.body[fieldKey] ?? '').trim();
    }
    if ('tags' in req.body) {
      updates.tags = Array.isArray(req.body.tags) ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter(Boolean) : [];
    }
    if ('slug' in req.body || 'title' in req.body) {
      updates.slug = await ensureUniqueBlogSlug(String(req.body?.slug || req.body?.title || '').trim(), req.params.id);
    }
    if (updates.status === 'published') {
      updates.publishedAt = req.body?.publishedAt ? new Date(req.body.publishedAt) : new Date();
    }
    if (updates.status === 'draft') {
      updates.publishedAt = null;
    }
    const post = await BlogPost.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!post) return res.status(404).json({ error: 'Blog post not found' });
    return res.json({ post });
  } catch (error) {
    console.error('admin blog update error', error);
    return res.status(500).json({ error: 'Failed to update blog post' });
  }
});

app.delete('/api/admin/blog/posts/:id', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const deleted = await BlogPost.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Blog post not found' });
    await Promise.all([
      BlogComment.deleteMany({ postId: req.params.id }),
      BlogLike.deleteMany({ postId: req.params.id }),
    ]);
    return res.json({ deleted: true });
  } catch (error) {
    console.error('admin blog delete error', error);
    return res.status(500).json({ error: 'Failed to delete blog post' });
  }
});

app.patch('/api/admin/blog/posts/:id/publish', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const post = await BlogPost.findByIdAndUpdate(
      req.params.id,
      { status: 'published', publishedAt: new Date(), updatedAt: new Date() },
      { new: true },
    );
    if (!post) return res.status(404).json({ error: 'Blog post not found' });
    return res.json({ post });
  } catch (error) {
    console.error('admin blog publish error', error);
    return res.status(500).json({ error: 'Failed to publish blog post' });
  }
});

app.patch('/api/admin/blog/posts/:id/unpublish', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const post = await BlogPost.findByIdAndUpdate(
      req.params.id,
      { status: 'draft', updatedAt: new Date() },
      { new: true },
    );
    if (!post) return res.status(404).json({ error: 'Blog post not found' });
    return res.json({ post });
  } catch (error) {
    console.error('admin blog unpublish error', error);
    return res.status(500).json({ error: 'Failed to unpublish blog post' });
  }
});

app.post('/api/blog/:postId/like', async (req: Request, res: Response) => {
  try {
    const { postId } = req.params;
    const browserUuid = String(req.body?.browserUuid || '').trim();
    if (!browserUuid) return res.status(400).json({ error: 'browserUuid is required' });
    const existingLike = await BlogLike.findOne({ postId, browserUuid });
    if (existingLike) return res.status(409).json({ error: 'Already liked' });
    await BlogLike.create({ postId, browserUuid });
    const likeCount = await BlogLike.countDocuments({ postId });
    return res.json({ liked: true, likeCount });
  } catch (error) {
    console.error('blog like error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/blog/:postId/like', async (req: Request, res: Response) => {
  try {
    const { postId } = req.params;
    const browserUuid = String(req.body?.browserUuid || '').trim();
    if (!browserUuid) return res.status(400).json({ error: 'browserUuid is required' });
    const result = await BlogLike.deleteOne({ postId, browserUuid });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Like not found' });
    const likeCount = await BlogLike.countDocuments({ postId });
    return res.json({ liked: false, likeCount });
  } catch (error) {
    console.error('blog unlike error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/blog/:postId/likes', async (req: Request, res: Response) => {
  try {
    const { postId } = req.params;
    const browserUuid = String(req.query?.browserUuid || '').trim();
    const likeCount = await BlogLike.countDocuments({ postId });
    const isLiked = browserUuid ? Boolean(await BlogLike.exists({ postId, browserUuid })) : false;
    return res.json({ likeCount, isLiked });
  } catch (error) {
    console.error('blog likes fetch error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/blog/:postId/comments', async (req: Request, res: Response) => {
  try {
    const { postId } = req.params;
    const page = parseInt(req.query.page as string || '1', 10);
    const limit = Math.min(parseInt(req.query.limit as string || '10', 10), 50);
    const skip = (page - 1) * limit;
    const comments = await BlogComment.find({ postId, parentId: null, status: 'approved' }).sort({ created_at: -1 }).skip(skip).limit(limit).lean();
    const commentsWithReplies = await Promise.all(
      comments.map(async (comment: any) => {
        const replies = await BlogComment.find({ parentId: comment._id.toString(), status: 'approved' }).sort({ created_at: 1 }).lean();
        return {
          ...comment,
          guestEmail: undefined,
          replies: replies.map((reply: any) => ({ ...reply, guestEmail: undefined })),
          replyCount: replies.length,
        };
      }),
    );
    const totalComments = await BlogComment.countDocuments({ postId, parentId: null, status: 'approved' });
    return res.json({
      comments: commentsWithReplies,
      pagination: { page, limit, total: totalComments, pages: Math.ceil(totalComments / limit) },
    });
  } catch (error) {
    console.error('blog comments fetch error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/blog/:postId/comments', blogCommentLimiter, async (req: Request, res: Response) => {
  try {
    const { postId } = req.params;
    const website = String(req.body?.website || '').trim();
    if (website) return res.status(201).json({ success: true });

    const content = String(req.body?.content || '').trim();
    if (!content) return res.status(400).json({ error: 'Comment content is required' });
    if (content.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000 characters)' });

    const userId = String(req.body?.userId || '').trim();
    if (userId) {
      const user = await User.findById(userId);
      if (user) {
        const comment = await BlogComment.create({
          postId,
          userId,
          author: validator.escape(String(req.body?.author || user.name)),
          content,
          parentId: req.body?.parentId ? String(req.body.parentId) : null,
          status: 'approved',
        });
        return res.status(201).json(comment);
      }
    }

    const guestName = String(req.body?.guestName || '').trim();
    const browserUuid = String(req.body?.browserUuid || '').trim();
    if (!guestName || !browserUuid) return res.status(400).json({ error: 'guestName and browserUuid are required' });
    const comment = await BlogComment.create({
      postId,
      userId: browserUuid,
      author: validator.escape(guestName),
      guestEmail: String(req.body?.guestEmail || '').trim(),
      content,
      parentId: req.body?.parentId ? String(req.body.parentId) : null,
      browserUuid,
      status: 'pending',
    });
    return res.status(201).json(comment);
  } catch (error) {
    console.error('blog comment create error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/blog/comments/:commentId', async (req: Request, res: Response) => {
  try {
    const { commentId } = req.params;
    const { userId, content } = req.body;
    if (!userId || !content) return res.status(400).json({ error: 'User ID and content are required' });
    if (String(content).length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000 characters)' });
    const comment = await BlogComment.findOneAndUpdate(
      { _id: commentId, userId },
      { content: String(content), updated_at: new Date() },
      { new: true },
    );
    if (!comment) return res.status(404).json({ error: 'Comment not found or not authorized' });
    return res.json(comment);
  } catch (error) {
    console.error('blog comment update error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/blog/comments/:commentId', async (req: Request, res: Response) => {
  try {
    const { commentId } = req.params;
    const { userId } = req.body;
    if (!userId) return res.status(401).json({ error: 'User ID required' });
    const comment = await BlogComment.findOne({ _id: commentId, userId });
    if (!comment) return res.status(404).json({ error: 'Comment not found or not authorized' });
    await BlogComment.deleteMany({ $or: [{ _id: commentId }, { parentId: commentId }] });
    return res.json({ deleted: true });
  } catch (error) {
    console.error('blog comment delete error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/blog/comments', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const postId = String(req.query?.postId || '').trim();
    const filter: Record<string, any> = { status: 'pending' };
    if (postId) filter.postId = postId;
    const comments = await BlogComment.find(filter).sort({ created_at: -1 }).lean();
    const posts = await BlogPost.find({ _id: { $in: comments.map((comment: any) => comment.postId) } }).select('_id title slug').lean();
    const postMap = new Map(posts.map((post: any) => [String(post._id), post]));
    return res.json({
      comments: comments.map((comment: any) => ({
        ...comment,
        guestEmail: undefined,
        postTitle: postMap.get(String(comment.postId))?.title || '',
        postSlug: postMap.get(String(comment.postId))?.slug || '',
      })),
    });
  } catch (error) {
    console.error('admin pending comments error', error);
    return res.status(500).json({ error: 'Failed to fetch pending comments' });
  }
});

app.patch('/api/admin/blog/comments/:id/approve', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const updated = await BlogComment.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Comment not found' });
    return res.json({ success: true });
  } catch (error) {
    console.error('comment approve error', error);
    return res.status(500).json({ error: 'Failed to approve comment' });
  }
});

app.patch('/api/admin/blog/comments/:id/reject', async (req: Request, res: Response) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;
    const updated = await BlogComment.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Comment not found' });
    return res.json({ success: true });
  } catch (error) {
    console.error('comment reject error', error);
    return res.status(500).json({ error: 'Failed to reject comment' });
  }
});

async function start() {
  try {
    const uri = String(process.env.MONGODB_URI || '').trim();
    const hasConfiguredMongoUri = uri.length > 0
      && uri !== 'your_mongodb_connection_string_here'
      && (uri.startsWith('mongodb://') || uri.startsWith('mongodb+srv://'));
    if (!hasConfiguredMongoUri) {
      console.warn('Warning: MONGODB_URI not configured. Starting without MongoDB connection.');
    } else {
      await mongoose.connect(uri);
      console.log('Connected to MongoDB');
      await ensureDecisionConfig();
      await seedEmailTemplates();
    }
    app.listen(PORT, () => {
      console.log(`KC backend listening on http://localhost:${PORT}`);
    });
  } catch (e) {
    console.error('Failed to start server', e);
    process.exit(1);
  }
}

start();
