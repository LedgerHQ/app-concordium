module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    moduleFileExtensions: ['js', 'ts', 'json'],
    moduleDirectories: ['node_modules'],
    globals: {
        'ts-jest': {
            tsconfig: 'tsconfig.jest.json',
        },
    },
    testTimeout: 30000,
    globalSetup: '<rootDir>/globalSetup.js'
};
