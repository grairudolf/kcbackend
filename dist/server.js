import express from 'express';
import cors from 'cors';
import axios from 'axios';
import dotenv from 'dotenv';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash, createHmac } from 'crypto';
import mongoose, { Schema, model } from 'mongoose';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';
import validator from 'validator';
import { body, validationResult } from 'express-validator';
dotenv.config();
mongoose.set('bufferCommands', false);
const app = express();
const PORT = Number(process.env.PORT || 8080);
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';
const NKWA_BASE_URL = process.env.NKWA_BASE_URL || 'https://api.mynkwa.com';
const NKWA_API_KEY = process.env.NKWA_API_KEY || '';
const APP_BASE_URL = process.env.APP_BASE_URL || CORS_ORIGIN;
const BACKEND_PUBLIC_URL = process.env.BACKEND_PUBLIC_URL || `http://localhost:${PORT}`;
const APP_AUTH_SECRET = process.env.APP_AUTH_SECRET || 'dev-only-secret-change-in-prod';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev';
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
app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);
app.use('/api/stem/register', authLimiter);
app.use('/api/nkwa/webhook', authLimiter);
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(cors({
    origin: function (origin, callback) {
        if (!origin)
            return callback(null, true);
        const allowedOrigins = [
            CORS_ORIGIN,
            'http://localhost:5173',
            'http://localhost:3000',
            'https://localhost:5173',
            'https://localhost:3000',
        ];
        if (allowedOrigins.includes(origin))
            return callback(null, true);
        return callback(new Error('Not allowed by CORS'), false);
    },
    credentials: true,
}));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
const STEM_GRADES = ['Form 1', 'Form 2', 'Form 3', 'Form 4', 'Form 5', 'Lower Sixth', 'Upper Sixth'];
const STEM_PAYMENT_METHODS = ['mtn', 'orange'];
function normalizeCameroonPhone(raw) {
    const digits = String(raw || '').replace(/[^\d+]/g, '').trim();
    if (!digits)
        return null;
    if (/^\+237[6-9]\d{8}$/.test(digits))
        return digits;
    if (/^237[6-9]\d{8}$/.test(digits))
        return `+${digits}`;
    if (/^[6-9]\d{8}$/.test(digits))
        return `+237${digits}`;
    return null;
}
function splitFullName(fullName) {
    const parts = fullName.split(/\s+/).filter(Boolean);
    if (parts.length < 2)
        return null;
    return {
        firstName: parts[0],
        lastName: parts.slice(1).join(' '),
    };
}
function normalizeStemRegistrationPayload(payload) {
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
    const paymentMethod = String(payload?.paymentMethod || '').trim().toLowerCase();
    const gender = String(payload?.gender || '').trim().toLowerCase();
    const level = String(payload?.level || '').trim().toLowerCase();
    const dobISO = String(payload?.dobISO || '').trim();
    const region = String(payload?.region || '').trim();
    const examLocation = String(payload?.examLocation || '').trim();
    const expectations = String(payload?.expectations || payload?.motivation || '').trim();
    const subjects = Array.isArray(payload?.subjects) ? payload.subjects.map((item) => String(item).trim()).filter(Boolean) : [];
    if (!firstName || firstName.length < 2 || !/^[a-zA-Z\s'-]+$/.test(firstName))
        return { error: 'First name must be at least 2 valid characters' };
    if (!lastName || lastName.length < 2 || !/^[a-zA-Z\s'-]+$/.test(lastName))
        return { error: 'Last name must be at least 2 valid characters' };
    if (!validator.isEmail(email))
        return { error: 'Please provide a valid email address' };
    if (!studentPhone)
        return { error: 'Student phone number must be a valid Cameroonian number' };
    if (!payerPhone)
        return { error: 'Payer phone number must be a valid Cameroonian number' };
    if (guardianPhone === null && payload?.guardianPhone)
        return { error: 'Guardian phone number must be a valid Cameroonian number' };
    if (!school || school.length < 2 || school.length > 100)
        return { error: 'School name must be between 2 and 100 characters' };
    if (!STEM_GRADES.includes(grade))
        return { error: 'Please select a valid grade level' };
    if (!STEM_PAYMENT_METHODS.includes(paymentMethod))
        return { error: 'Payment method must be either MTN or Orange' };
    if (dobISO && Number.isNaN(new Date(dobISO).getTime()))
        return { error: 'Date of birth must be a valid ISO date' };
    if (gender && !['male', 'female', 'other'].includes(gender))
        return { error: 'Gender must be male, female, or other' };
    if (level && !['olevel', 'alevel'].includes(level))
        return { error: 'Level must be olevel or alevel' };
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
            grade: grade,
            paymentMethod,
            schoolClass: String(payload?.schoolClass || grade).trim(),
            level,
            region,
            examLocation,
            expectations,
            subjects,
        },
    };
}
const validateRegistration = [
    body('payload').custom((payload) => {
        const normalized = normalizeStemRegistrationPayload(payload);
        if ('error' in normalized)
            throw new Error(normalized.error);
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
        validate: { validator: (email) => validator.isEmail(email), message: 'Please provide a valid email address' },
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
        email: { type: String, required: true, validate: { validator: (email) => validator.isEmail(email), message: 'Please provide a valid email address' } },
        phone: { type: String, required: true, validate: { validator: (phone) => /^\+237[6-9]\d{8}$/.test(phone), message: 'Phone number must be in Cameroon format: +237XXXXXXXXX' } },
        payerPhone: { type: String, required: true, validate: { validator: (phone) => /^\+237[6-9]\d{8}$/.test(phone), message: 'Payer phone number must be in Cameroon format: +237XXXXXXXXX' } },
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
    userId: { type: String, required: true, index: true },
    created_at: { type: Date, default: Date.now },
});
BlogLikeSchema.index({ postId: 1, userId: 1 }, { unique: true });
const BlogLike = model('BlogLike', BlogLikeSchema);
const BlogCommentSchema = new Schema({
    postId: { type: String, required: true, index: true },
    userId: { type: String, required: true },
    author: {
        type: String,
        required: true,
        maxlength: 50,
        validate: { validator: (name) => /^[a-zA-Z\s'-]+$/.test(name), message: 'Author name can only contain letters, spaces, hyphens, and apostrophes' },
    },
    content: {
        type: String,
        required: true,
        maxlength: 1000,
        validate: { validator: (content) => content.trim().length > 0, message: 'Comment content cannot be empty' },
    },
    parentId: { type: String, default: null },
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
const AuthTokenSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['verify_email', 'reset_password'], required: true, index: true },
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
function makeTokenHash(raw) {
    return createHash('sha256').update(raw).digest('hex');
}
function passwordHash(password) {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash)
        return false;
    const incoming = scryptSync(password, salt, 64);
    const original = Buffer.from(hash, 'hex');
    if (incoming.length !== original.length)
        return false;
    return timingSafeEqual(incoming, original);
}
function b64url(data) {
    return Buffer.from(data).toString('base64url');
}
function createSessionToken(payload) {
    const body = b64url(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
    const sig = createHmac('sha256', APP_AUTH_SECRET).update(body).digest('base64url');
    return `${body}.${sig}`;
}
function verifySessionToken(token) {
    const parts = token.split('.');
    if (parts.length !== 2)
        return null;
    const [body, sig] = parts;
    const expected = createHmac('sha256', APP_AUTH_SECRET).update(body).digest('base64url');
    if (sig !== expected)
        return null;
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!parsed.exp || parsed.exp < Date.now())
        return null;
    return { userId: parsed.userId, role: parsed.role, email: parsed.email };
}
function getBearerToken(req) {
    const raw = req.headers.authorization;
    if (!raw || !raw.startsWith('Bearer '))
        return null;
    return raw.slice(7).trim();
}
function isDatabaseConnected() {
    return mongoose.connection.readyState === 1;
}
function requireDatabase(_req, res, next) {
    if (!isDatabaseConnected()) {
        return res.status(503).json({ error: 'Database unavailable', message: 'Configure a valid MongoDB connection to use this endpoint.' });
    }
    next();
}
function countWords(value) {
    return value.trim().split(/\s+/).filter(Boolean).length;
}
async function sendEmail(to, subject, html, type, userId, meta) {
    const log = await EmailLog.create({ userId, email: to, type, status: 'queued', meta });
    if (!RESEND_API_KEY) {
        await EmailLog.updateOne({ _id: log._id }, { status: 'failed', error: 'RESEND_API_KEY missing' });
        return false;
    }
    try {
        const resp = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${RESEND_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                from: RESEND_FROM_EMAIL,
                to: [to],
                subject,
                html,
            }),
        });
        if (!resp.ok) {
            const text = await resp.text();
            await EmailLog.updateOne({ _id: log._id }, { status: 'failed', error: text.slice(0, 500) });
            return false;
        }
        await EmailLog.updateOne({ _id: log._id }, { status: 'sent' });
        return true;
    }
    catch (error) {
        await EmailLog.updateOne({ _id: log._id }, { status: 'failed', error: String(error?.message || error) });
        return false;
    }
}
async function ensureDecisionConfig() {
    const key = 'gsp-2026';
    const existing = await DecisionRelease.findOne({ key });
    if (existing)
        return existing;
    return DecisionRelease.create({ key, isReleased: false, releasedAt: null, updatedAt: new Date() });
}
function computeProgress(sectionState) {
    const sections = ['section1', 'section2', 'section3', 'section4', 'section5', 'section6', 'section8', 'section9', 'section10', 'review'];
    const done = sections.filter((s) => sectionState?.[s]).length;
    return Math.round((done / sections.length) * 100);
}
function getValidationErrorsForSubmit(data) {
    const errors = [];
    const isEmpty = (v) => v === null || v === undefined || String(v).trim() === '';
    const requireField = (value, label) => {
        if (isEmpty(value))
            errors.push(`${label} is required`);
    };
    const requireWordMax = (value, max, label) => {
        if (isEmpty(value))
            return;
        if (countWords(String(value)) > max)
            errors.push(`${label} must be ${max} words or less`);
    };
    const requireWordRange = (value, min, max, label) => {
        const words = countWords(String(value || ''));
        if (words < min || words > max)
            errors.push(`${label} must be between ${min} and ${max} words`);
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
    if (data?.familyStudiedAbroad === 'yes')
        requireWordMax(data?.familyAbroadDetails, 150, 'Family abroad details');
    requireField(data?.schoolName, 'School name');
    requireField(data?.schoolCity, 'School city');
    requireField(data?.schoolRegion, 'School region');
    requireField(data?.currentClass, 'Current form/class');
    if (data?.currentClass === 'lower_sixth')
        requireField(data?.lowerSixthPathwayChoice, 'Lower Sixth pathway choice');
    if (!Array.isArray(data?.topSubjects) || data.topSubjects.length !== 5)
        errors.push('You must provide exactly 5 strongest subjects');
    else {
        data.topSubjects.forEach((subject, idx) => {
            requireField(subject?.name, `Subject ${idx + 1} name`);
            requireField(subject?.score, `Subject ${idx + 1} score`);
            requireField(subject?.examTerm, `Subject ${idx + 1} exam/term`);
        });
    }
    requireField(data?.intendedFieldWhy, 'Intended university field essay');
    requireWordMax(data?.intendedFieldWhy, 150, 'Intended university field essay');
    requireField(data?.communityEssay, 'Short answer response');
    requireWordRange(data?.communityEssay, 75, 225, 'Short answer response');
    if (!Array.isArray(data?.activities) || data.activities.length < 1 || data.activities.length > 3)
        errors.push('Provide between 1 and 3 activities');
    else {
        data.activities.forEach((activity, idx) => {
            requireField(activity?.title, `Activity ${idx + 1} title`);
            requireField(activity?.roleDescription, `Activity ${idx + 1} role description`);
            requireField(activity?.duration, `Activity ${idx + 1} duration`);
            requireField(activity?.hoursPerWeek, `Activity ${idx + 1} hours per week`);
            requireField(activity?.weeksPerYear, `Activity ${idx + 1} weeks per year`);
            requireField(activity?.isStillDoing, `Activity ${idx + 1} current status`);
            if (activity?.isStillDoing === 'no')
                requireField(activity?.stoppedIn, `Activity ${idx + 1} stop date`);
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
    if (data?.participationConstraint === 'yes')
        requireWordMax(data?.participationConstraintExplain, 200, 'Participation constraints explanation');
    requireField(data?.monthlyIncomeRange, 'Monthly household income');
    requireField(data?.worksToSupportFamily, 'Work support question');
    if (data?.worksToSupportFamily === 'yes')
        requireWordMax(data?.workSupportDetails, 100, 'Work support details');
    requireField(data?.costChallenge, 'Programme cost challenge response');
    requireField(data?.applyingScholarship, 'Scholarship intent');
    if (data?.applyingScholarship === 'yes')
        requireField(data?.scholarshipEssay, 'Scholarship essay');
    requireField(data?.documents?.reportCard?.url, 'Report card document');
    requireField(data?.documents?.olSlip?.url, 'O-Level slip document');
    if (data?.declarationConfirmed !== true)
        errors.push('Declaration confirmation is required');
    return errors;
}
async function requireAuth(req, res) {
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
async function requireAdmin(req, res) {
    const auth = await requireAuth(req, res);
    if (!auth)
        return null;
    if (auth.role !== 'admin') {
        res.status(403).json({ error: 'Admin access required' });
        return null;
    }
    return auth;
}
app.get('/health', async (_req, res) => {
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
        }
        else {
            healthCheck.ok = false;
            healthCheck.database = 'disconnected';
        }
    }
    catch (_error) {
        healthCheck.ok = false;
        healthCheck.database = 'error';
    }
    if (NKWA_API_KEY) {
        try {
            await axios.get(`${NKWA_BASE_URL}/health`, { headers: { Authorization: `Bearer ${NKWA_API_KEY}` }, timeout: 5000 });
            healthCheck.services.nkwa = true;
        }
        catch (_error) {
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
app.post('/api/newsletter', body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'), async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty())
            return res.status(400).json({ error: 'Validation failed', details: errors.array() });
        const { email } = req.body;
        if (!email || !validator.isEmail(email))
            return res.status(400).json({ error: 'Invalid email address' });
        const normalizedEmail = email.toLowerCase().trim();
        const existingSubscriber = await Subscriber.findOne({ email: normalizedEmail });
        if (existingSubscriber)
            return res.status(409).json({ error: 'Email already subscribed' });
        await Subscriber.create({ email: normalizedEmail, created_at: new Date() });
        return res.json({ success: true, message: 'Successfully subscribed to newsletter' });
    }
    catch (error) {
        console.error('Newsletter subscription error:', error);
        return res.status(500).json({ error: 'Internal server error', message: 'Failed to subscribe to newsletter' });
    }
});
app.post('/api/auth/register', async (req, res) => {
    try {
        const name = String(req.body?.name || '').trim();
        const email = String(req.body?.email || '').toLowerCase().trim();
        const password = String(req.body?.password || '');
        if (!name || name.length < 2)
            return res.status(400).json({ error: 'Name must be at least 2 characters' });
        if (!validator.isEmail(email))
            return res.status(400).json({ error: 'Valid email required' });
        if (password.length < 8)
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        const existing = await User.findOne({ email });
        if (existing)
            return res.status(409).json({ error: 'Email already exists' });
        const role = ADMIN_EMAIL_ALLOWLIST.includes(email) ? 'admin' : 'student';
        const user = await User.create({
            name: validator.escape(name),
            email,
            passwordHash: passwordHash(password),
            role,
            isEmailVerified: false,
            created_at: new Date(),
        });
        const rawToken = `${randomUUID()}${randomBytes(12).toString('hex')}`;
        await AuthToken.create({
            userId: user._id,
            type: 'verify_email',
            tokenHash: makeTokenHash(rawToken),
            expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
            created_at: new Date(),
        });
        const verifyLink = `${APP_BASE_URL}/gsp?verifyToken=${encodeURIComponent(rawToken)}`;
        await sendEmail(email, 'Verify your KC GSP account', `<p>Hello ${validator.escape(name)},</p><p>Verify your email to activate your KC GSP portal account.</p><p><a href="${verifyLink}">Verify email</a></p><p>This link expires in 24 hours.</p>`, 'auth_verify_email', String(user._id), { verifyLink });
        return res.status(201).json({
            success: true,
            message: 'Account created. Please verify your email.',
            ...(process.env.NODE_ENV !== 'production' ? { debugVerifyToken: rawToken } : {}),
        });
    }
    catch (error) {
        console.error('register error', error);
        return res.status(500).json({ error: 'Failed to create account' });
    }
});
app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const token = String(req.body?.token || '');
        if (!token)
            return res.status(400).json({ error: 'Token is required' });
        const tokenDoc = await AuthToken.findOne({
            tokenHash: makeTokenHash(token),
            type: 'verify_email',
            usedAt: null,
            expiresAt: { $gt: new Date() },
        });
        if (!tokenDoc)
            return res.status(400).json({ error: 'Token is invalid or expired' });
        await User.updateOne({ _id: tokenDoc.userId }, { isEmailVerified: true });
        await AuthToken.updateOne({ _id: tokenDoc._id }, { usedAt: new Date() });
        return res.json({ success: true, message: 'Email verified successfully' });
    }
    catch (error) {
        console.error('verify email error', error);
        return res.status(500).json({ error: 'Failed to verify email' });
    }
});
app.post('/api/auth/login', async (req, res) => {
    try {
        const email = String(req.body?.email || '').toLowerCase().trim();
        const password = String(req.body?.password || '');
        if (!validator.isEmail(email) || !password)
            return res.status(400).json({ error: 'Email and password are required' });
        const user = await User.findOne({ email });
        if (!user || !verifyPassword(password, user.passwordHash))
            return res.status(401).json({ error: 'Invalid credentials' });
        if (!user.isEmailVerified)
            return res.status(403).json({ error: 'Please verify your email before login' });
        await User.updateOne({ _id: user._id }, { lastLoginAt: new Date() });
        const token = createSessionToken({ userId: String(user._id), role: user.role, email: user.email });
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
    }
    catch (error) {
        console.error('login error', error);
        return res.status(500).json({ error: 'Failed to login' });
    }
});
app.post('/api/auth/logout', async (_req, res) => {
    return res.json({ success: true });
});
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const email = String(req.body?.email || '').toLowerCase().trim();
        if (!validator.isEmail(email))
            return res.json({ success: true });
        const user = await User.findOne({ email });
        if (!user)
            return res.json({ success: true });
        const rawToken = `${randomUUID()}${randomBytes(12).toString('hex')}`;
        await AuthToken.create({
            userId: user._id,
            type: 'reset_password',
            tokenHash: makeTokenHash(rawToken),
            expiresAt: new Date(Date.now() + 1000 * 60 * 30),
            created_at: new Date(),
        });
        const resetLink = `${APP_BASE_URL}/gsp?resetToken=${encodeURIComponent(rawToken)}`;
        await sendEmail(user.email, 'Reset your KC GSP password', `<p>Hello ${validator.escape(user.name)},</p><p>Use this link to reset your password.</p><p><a href="${resetLink}">Reset password</a></p><p>This link expires in 30 minutes.</p>`, 'auth_reset_password', String(user._id), { resetLink });
        return res.json({
            success: true,
            ...(process.env.NODE_ENV !== 'production' ? { debugResetToken: rawToken } : {}),
        });
    }
    catch (error) {
        console.error('forgot password error', error);
        return res.status(500).json({ error: 'Failed to request password reset' });
    }
});
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const token = String(req.body?.token || '');
        const newPassword = String(req.body?.newPassword || '');
        if (!token || newPassword.length < 8)
            return res.status(400).json({ error: 'Token and valid password are required' });
        const tokenDoc = await AuthToken.findOne({
            tokenHash: makeTokenHash(token),
            type: 'reset_password',
            usedAt: null,
            expiresAt: { $gt: new Date() },
        });
        if (!tokenDoc)
            return res.status(400).json({ error: 'Token is invalid or expired' });
        await User.updateOne({ _id: tokenDoc.userId }, { passwordHash: passwordHash(newPassword) });
        await AuthToken.updateOne({ _id: tokenDoc._id }, { usedAt: new Date() });
        return res.json({ success: true });
    }
    catch (error) {
        console.error('reset password error', error);
        return res.status(500).json({ error: 'Failed to reset password' });
    }
});
app.get('/api/auth/me', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
    const user = await User.findById(auth.userId);
    if (!user)
        return res.status(404).json({ error: 'User not found' });
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
app.get('/api/gsp/application', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
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
    return res.json({ application: existing });
});
app.put('/api/gsp/application/draft', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
    const data = req.body?.data || {};
    const sectionState = req.body?.sectionState || {};
    const progressPct = computeProgress(sectionState);
    const existing = await GspApplication.findOne({ userId: auth.userId });
    if (existing?.status === 'submitted')
        return res.status(409).json({ error: 'Application already submitted and locked' });
    const updated = await GspApplication.findOneAndUpdate({ userId: auth.userId }, {
        $set: { data, sectionState, progressPct, status: 'draft', updated_at: new Date() },
        $setOnInsert: { userId: auth.userId, created_at: new Date() },
    }, { upsert: true, new: true });
    return res.json({ success: true, application: updated });
});
app.post('/api/gsp/application/submit', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
    const data = req.body?.data || {};
    const sectionState = req.body?.sectionState || {};
    const errors = getValidationErrorsForSubmit(data);
    if (errors.length > 0)
        return res.status(400).json({ error: 'Validation failed', details: errors });
    const existing = await GspApplication.findOne({ userId: auth.userId });
    if (existing?.status === 'submitted')
        return res.status(409).json({ error: 'Application already submitted' });
    const reference = `KC-GSP-${new Date().getFullYear()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    const progressPct = computeProgress({ ...sectionState, review: true });
    const saved = await GspApplication.findOneAndUpdate({ userId: auth.userId }, {
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
    }, { upsert: true, new: true });
    const user = await User.findById(auth.userId);
    if (user) {
        await sendEmail(user.email, 'KC GSP Application Submitted', `<p>Hello ${validator.escape(user.name)},</p><p>Your KC Global Scholars Programme application has been submitted successfully.</p><p><strong>Reference:</strong> ${reference}</p><p>You can now track your status from your dashboard.</p>`, 'gsp_submission_confirmation', String(user._id), { reference });
    }
    return res.json({ success: true, reference, application: saved });
});
app.get('/api/gsp/application/decision', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
    const appRecord = await GspApplication.findOne({ userId: auth.userId });
    if (!appRecord)
        return res.status(404).json({ error: 'Application not found' });
    const release = await ensureDecisionConfig();
    if (!release.isReleased)
        return res.json({ released: false, decisionStatus: null });
    return res.json({
        released: true,
        decisionStatus: appRecord.decisionStatus,
        submittedAt: appRecord.submittedAt,
        reference: appRecord.reference,
        lowerSixthPathwayChoice: appRecord.data?.lowerSixthPathwayChoice || null,
    });
});
app.post('/api/gsp/uploads', async (req, res) => {
    const auth = await requireAuth(req, res);
    if (!auth)
        return;
    const fileName = String(req.body?.fileName || '');
    const mimeType = String(req.body?.mimeType || '');
    const dataUrl = String(req.body?.dataUrl || '');
    const allowed = ['application/pdf', 'image/jpeg', 'image/png'];
    if (!allowed.includes(mimeType))
        return res.status(400).json({ error: 'Unsupported file type' });
    if (!dataUrl.startsWith('data:'))
        return res.status(400).json({ error: 'Invalid file payload' });
    const binaryLength = Buffer.from(dataUrl.split(',')[1] || '', 'base64').length;
    if (binaryLength > 10 * 1024 * 1024)
        return res.status(400).json({ error: 'File exceeds 10MB size limit' });
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
        const cloudData = await cloudResp.json();
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
    }
    catch (error) {
        return res.status(500).json({ error: 'Upload failed', details: String(error?.message || error) });
    }
});
app.get('/api/admin/gsp/applications', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const query = String(req.query?.query || '').trim();
    const status = String(req.query?.status || '').trim();
    const decisionStatus = String(req.query?.decisionStatus || '').trim();
    const baseFilter = {};
    if (status)
        baseFilter.status = status;
    if (decisionStatus)
        baseFilter.decisionStatus = decisionStatus;
    if (query) {
        const users = await User.find({
            $or: [
                { email: { $regex: query, $options: 'i' } },
                { name: { $regex: query, $options: 'i' } },
            ],
        }).select('_id');
        baseFilter.userId = { $in: users.map((u) => u._id) };
    }
    const applications = await GspApplication.find(baseFilter).sort({ submittedAt: -1, updated_at: -1 }).lean();
    const userIds = applications.map((a) => a.userId);
    const users = await User.find({ _id: { $in: userIds } }).lean();
    const userMap = new Map(users.map((u) => [String(u._id), u]));
    const merged = applications.map((a) => ({
        ...a,
        user: (() => {
            const user = userMap.get(String(a.userId));
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
});
app.get('/api/admin/gsp/applications/:id', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const appRecord = await GspApplication.findById(req.params.id).lean();
    if (!appRecord)
        return res.status(404).json({ error: 'Application not found' });
    const user = await User.findById(appRecord.userId).lean();
    return res.json({
        application: appRecord,
        user: user ? {
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
            isEmailVerified: user.isEmailVerified,
            lastLoginAt: user.lastLoginAt,
        } : null,
    });
});
app.patch('/api/admin/gsp/applications/:id/decision', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const decisionStatus = String(req.body?.decisionStatus || '');
    if (!['accepted', 'waitlisted', 'not_admitted', 'pending'].includes(decisionStatus)) {
        return res.status(400).json({ error: 'Invalid decision status' });
    }
    const updated = await GspApplication.findByIdAndUpdate(req.params.id, { decisionStatus, decisionUpdatedAt: new Date(), updated_at: new Date() }, { new: true });
    if (!updated)
        return res.status(404).json({ error: 'Application not found' });
    return res.json({ success: true, application: updated });
});
app.patch('/api/admin/gsp/release', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const isReleased = !!req.body?.isReleased;
    const current = await ensureDecisionConfig();
    const wasReleased = current.isReleased;
    const updated = await DecisionRelease.findOneAndUpdate({ key: 'gsp-2026' }, { isReleased, releasedAt: isReleased ? new Date() : null, updatedAt: new Date() }, { new: true });
    if (!wasReleased && isReleased) {
        const apps = await GspApplication.find({ status: 'submitted', decisionStatus: { $in: ['accepted', 'waitlisted', 'not_admitted'] } }).lean();
        const userIds = apps.map((a) => a.userId);
        const users = await User.find({ _id: { $in: userIds } }).lean();
        const userMap = new Map(users.map((u) => [String(u._id), u]));
        for (const appRec of apps) {
            const user = userMap.get(String(appRec.userId));
            if (!user)
                continue;
            await sendEmail(user.email, 'KC GSP Decision Update', `<p>Hello ${validator.escape(user.name)},</p><p>Your KC Global Scholars Programme decision is now available in your portal dashboard.</p><p>Please sign in to view your decision.</p>`, 'gsp_decision_release', String(user._id), { applicationId: String(appRec._id), decisionStatus: appRec.decisionStatus });
        }
    }
    return res.json({ success: true, release: updated });
});
app.get('/api/admin/gsp/release', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const release = await ensureDecisionConfig();
    return res.json({ release });
});
app.get('/api/admin/gsp/users', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    const users = await User.find({}).sort({ created_at: -1 }).lean();
    return res.json({
        users: users.map((user) => ({
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
app.post('/api/stem/register', validateRegistration, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty())
            return res.status(400).json({ error: 'Validation failed', details: errors.array() });
        const { payload, amount } = req.body;
        if (!payload || !amount)
            return res.status(400).json({ error: 'Missing required fields', message: 'Payload and amount are required' });
        const normalized = normalizeStemRegistrationPayload(payload);
        if ('error' in normalized)
            return res.status(400).json({ error: normalized.error });
        if (!NKWA_API_KEY)
            return res.status(500).json({ error: 'Payment service unavailable', message: 'Payment integration not configured' });
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
            await Registration.updateOne({ reference }, { nkwaTransactionId: nkwaResponse.data?.transactionId, paymentDetails: nkwaResponse.data, status: 'processing', updated_at: new Date() });
            return res.json({
                reference,
                status: 'processing',
                message: 'Payment request initiated successfully',
                nkwaResponse: process.env.NODE_ENV === 'development' ? nkwaResponse.data : undefined,
            });
        }
        catch (nkwaError) {
            await Registration.updateOne({ reference }, { status: 'failed', paymentDetails: nkwaError.response?.data, updated_at: new Date() });
            return res.status(502).json({ error: 'Payment service error', message: 'Failed to initiate payment. Please try again.', reference });
        }
    }
    catch (error) {
        console.error('STEM registration error:', error);
        return res.status(500).json({ error: 'Internal server error', message: 'Failed to process registration' });
    }
});
app.post('/api/nkwa/webhook', express.json({ type: '*/*' }), async (req, res) => {
    try {
        const event = req.body;
        const { reference, status, transactionId } = event || {};
        if (!reference)
            return res.status(400).json({ error: 'Missing reference' });
        const updateData = {
            status: status === 'success' ? 'success' : 'failed',
            nkwaTransactionId: transactionId,
            paymentDetails: event,
            updated_at: new Date(),
        };
        if (status === 'success')
            updateData.completed_at = new Date();
        const result = await Registration.updateOne({ reference }, updateData);
        if (result.matchedCount === 0)
            return res.status(404).json({ error: 'Registration not found' });
        return res.json({ received: true, reference, status: updateData.status });
    }
    catch (error) {
        console.error('Webhook processing error:', error);
        return res.status(500).json({ error: 'Webhook processing failed', message: 'Failed to process payment notification' });
    }
});
app.get('/api/timeline', async (_req, res) => {
    try {
        const timeline = await TimelineItem.find({}).sort({ date_iso: 1 }).lean();
        return res.json(timeline);
    }
    catch (_error) {
        return res.status(500).json({ error: 'Failed to fetch timeline' });
    }
});
app.post('/api/timeline', async (req, res) => {
    const auth = await requireAdmin(req, res);
    if (!auth)
        return;
    try {
        const payload = {
            title: String(req.body?.title || '').trim(),
            description: String(req.body?.description || '').trim(),
            date_iso: new Date(req.body?.dateISO || req.body?.date_iso),
            tag: String(req.body?.tag || '').trim(),
            imageUrl: String(req.body?.imageUrl || '').trim(),
            linkUrl: String(req.body?.linkUrl || '').trim(),
        };
        if (!payload.title || Number.isNaN(payload.date_iso.getTime()))
            return res.status(400).json({ error: 'Invalid timeline payload' });
        const item = await TimelineItem.create(payload);
        return res.status(201).json(item);
    }
    catch (_error) {
        return res.status(500).json({ error: 'Failed to add timeline item' });
    }
});
app.post('/api/blog/:postId/like', async (req, res) => {
    try {
        const { postId } = req.params;
        const { userId } = req.body;
        if (!userId)
            return res.status(401).json({ error: 'User ID required' });
        const existingLike = await BlogLike.findOne({ postId, userId });
        if (existingLike)
            return res.status(409).json({ error: 'Already liked' });
        await BlogLike.create({ postId, userId });
        const likeCount = await BlogLike.countDocuments({ postId });
        res.json({ liked: true, likeCount });
    }
    catch (error) {
        console.error('Like error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.delete('/api/blog/:postId/like', async (req, res) => {
    try {
        const { postId } = req.params;
        const { userId } = req.body;
        if (!userId)
            return res.status(401).json({ error: 'User ID required' });
        const result = await BlogLike.deleteOne({ postId, userId });
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Like not found' });
        const likeCount = await BlogLike.countDocuments({ postId });
        res.json({ liked: false, likeCount });
    }
    catch (error) {
        console.error('Unlike error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/api/blog/:postId/likes', async (req, res) => {
    try {
        const { postId } = req.params;
        const { userId } = req.query;
        const likeCount = await BlogLike.countDocuments({ postId });
        const isLiked = userId ? Boolean(await BlogLike.exists({ postId, userId: userId })) : false;
        res.json({ likeCount, isLiked });
    }
    catch (error) {
        console.error('Get likes error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/api/blog/:postId/comments', async (req, res) => {
    try {
        const { postId } = req.params;
        const page = parseInt(req.query.page || '1');
        const limit = Math.min(parseInt(req.query.limit || '10'), 50);
        const skip = (page - 1) * limit;
        const comments = await BlogComment.find({ postId, parentId: null }).sort({ created_at: -1 }).skip(skip).limit(limit).lean();
        const commentsWithReplies = await Promise.all(comments.map(async (comment) => {
            const replies = await BlogComment.find({ parentId: comment._id.toString() }).sort({ created_at: 1 }).lean();
            return { ...comment, replies, replyCount: replies.length };
        }));
        const totalComments = await BlogComment.countDocuments({ postId, parentId: null });
        res.json({ comments: commentsWithReplies, pagination: { page, limit, total: totalComments, pages: Math.ceil(totalComments / limit) } });
    }
    catch (error) {
        console.error('Get comments error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/api/blog/:postId/comments', async (req, res) => {
    try {
        const { postId } = req.params;
        const { userId, author, content, parentId } = req.body;
        if (!userId || !author || !content)
            return res.status(400).json({ error: 'User ID, author, and content are required' });
        if (content.length > 1000)
            return res.status(400).json({ error: 'Comment too long (max 1000 characters)' });
        const comment = await BlogComment.create({ postId, userId, author, content, parentId: parentId || null });
        res.status(201).json(comment);
    }
    catch (error) {
        console.error('Add comment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.put('/api/blog/comments/:commentId', async (req, res) => {
    try {
        const { commentId } = req.params;
        const { userId, content } = req.body;
        if (!userId || !content)
            return res.status(400).json({ error: 'User ID and content are required' });
        if (content.length > 1000)
            return res.status(400).json({ error: 'Comment too long (max 1000 characters)' });
        const comment = await BlogComment.findOneAndUpdate({ _id: commentId, userId }, { content, updated_at: new Date() }, { new: true });
        if (!comment)
            return res.status(404).json({ error: 'Comment not found or not authorized' });
        res.json(comment);
    }
    catch (error) {
        console.error('Update comment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.delete('/api/blog/comments/:commentId', async (req, res) => {
    try {
        const { commentId } = req.params;
        const { userId } = req.body;
        if (!userId)
            return res.status(401).json({ error: 'User ID required' });
        const comment = await BlogComment.findOne({ _id: commentId, userId });
        if (!comment)
            return res.status(404).json({ error: 'Comment not found or not authorized' });
        await BlogComment.deleteMany({ $or: [{ _id: commentId }, { parentId: commentId }] });
        res.json({ deleted: true });
    }
    catch (error) {
        console.error('Delete comment error:', error);
        res.status(500).json({ error: 'Internal server error' });
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
        }
        else {
            await mongoose.connect(uri);
            console.log('Connected to MongoDB');
            await ensureDecisionConfig();
        }
        app.listen(PORT, () => {
            console.log(`KC backend listening on http://localhost:${PORT}`);
        });
    }
    catch (e) {
        console.error('Failed to start server', e);
        process.exit(1);
    }
}
start();
