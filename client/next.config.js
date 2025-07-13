/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    serverComponentsExternalPackages: ['libsodium-wrappers-sumo']
  }
};

module.exports = nextConfig;