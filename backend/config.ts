import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL || '',

  // Reddit integration
  reddit: {
    clientId: process.env.REDDIT_CLIENT_ID || 'public_mode',
    clientSecret: process.env.REDDIT_CLIENT_SECRET || 'public_mode',
    userAgent: process.env.REDDIT_USER_AGENT || 'FindOut-DRP-Scanner/1.0',
  },

  // YouTube integration
  youtube: {
    apiKey: process.env.YOUTUBE_API_KEY || '',
  },

  // Gemini AI integration
  gemini: {
    apiKey: process.env.GEMINI_API_KEY || '',
  },

  // Threat intelligence & URL safety integrations
  security: {
    safeBrowsingApiKey: process.env.SAFE_BROWSING_API_KEY || '',
    urlhausApiUrl: process.env.URLHAUS_API_URL || 'https://urlhaus-api.abuse.ch/v1',
  },

  // App store & crawler options
  monitoring: {
    maxLookalikeDistance: parseInt(process.env.MAX_LOOKALIKE_DISTANCE || '2', 10),
    similarityThreshold: parseFloat(process.env.SIMILARITY_THRESHOLD || '0.75'),
    enableGracefulMockFallback: process.env.ENABLE_MOCK_FALLBACK !== 'false',
  },
};

export default config;