/* eslint-disable */
module.exports = {
  displayName: 'lib',
  testEnvironment: 'node',
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'js'],
  moduleNameMapper: {
    '^@signet/lib$': '<rootDir>/../lib/src/index.ts',
    '^@signet/server/(.*)$': '<rootDir>/../server/src/$1',
  },
  testMatch: ['<rootDir>/src/**/__tests__/**/*.test.ts'],
  coverageDirectory: '../../coverage/lib',
};
