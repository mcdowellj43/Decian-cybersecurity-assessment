import { z } from 'zod';

// User registration validation schema
export const registerSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .min(1, 'Email is required')
    .max(255, 'Email must be less than 255 characters'),

  name: z
    .string()
    .min(1, 'Name is required')
    .max(100, 'Name must be less than 100 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters'),

  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters'),

  organizationName: z
    .string()
    .min(1, 'Organization name is required')
    .max(100, 'Organization name must be less than 100 characters')
    .optional(),
});

// User login validation schema
export const loginSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .min(1, 'Email is required'),

  password: z
    .string()
    .min(1, 'Password is required'),
});

// Refresh token validation schema
export const refreshTokenSchema = z.object({
  refreshToken: z
    .string()
    .min(1, 'Refresh token is required'),
});

// Change password validation schema
export const changePasswordSchema = z.object({
  currentPassword: z
    .string()
    .min(1, 'Current password is required'),

  newPassword: z
    .string()
    .min(8, 'New password must be at least 8 characters')
    .max(128, 'New password must be less than 128 characters'),
});

// Reset password validation schema
export const resetPasswordSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .min(1, 'Email is required'),
});

// Agent registration validation schema
export const agentRegistrationSchema = z.object({
  hostname: z
    .string()
    .min(1, 'Hostname is required')
    .max(255, 'Hostname must be less than 255 characters')
    .regex(/^[a-zA-Z0-9.-]+$/, 'Invalid hostname format'),

  version: z
    .string()
    .min(1, 'Agent version is required')
    .regex(/^\d+\.\d+\.\d+$/, 'Invalid version format (expected x.y.z)'),

  configuration: z
    .object({})
    .optional(),
});

// Assessment creation validation schema
export const createAssessmentSchema = z.object({
  agentId: z
    .string()
    .min(1, 'Agent ID is required'),

  modules: z
    .array(z.string())
    .min(1, 'At least one assessment module is required'),

  configuration: z
    .object({})
    .optional(),
});

// Report generation validation schema
export const generateReportSchema = z.object({
  assessmentId: z
    .string()
    .min(1, 'Assessment ID is required'),

  template: z
    .string()
    .optional(),

  includeRemediation: z
    .boolean()
    .optional(),

  includeTechnicalDetails: z
    .boolean()
    .optional(),
});

// Generic validation middleware
export const validateSchema = (schema: z.ZodSchema) => {
  return (req: any, res: any, next: any) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          status: 'fail',
          message: 'Validation failed',
          errors: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message,
          })),
        });
      }
      next(error);
    }
  };
};

// Organization validation schemas
export const createOrganizationSchema = z.object({
  name: z
    .string()
    .min(1, 'Organization name is required')
    .max(255, 'Organization name must be less than 255 characters'),

  settings: z
    .record(z.any())
    .optional()
    .default({}),
});

export const updateOrganizationSchema = z.object({
  name: z
    .string()
    .min(1, 'Organization name is required')
    .max(255, 'Organization name must be less than 255 characters')
    .optional(),

  settings: z
    .record(z.any())
    .optional(),
});

// Alias for validateSchema for consistency
export const validateRequest = validateSchema;