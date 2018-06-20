const path             = require('path');
const fs               = require('fs');
const os               = require('os');
const zlib             = require('zlib');
const npmFetch         = require('npm-registry-fetch');
const npmAuditReporter = require('npm-audit-report');
const { mapValues }    = require('lodash');

const NPM_AUDIT_API_PATH = '/-/npm/v1/security/audits';

const NPM_AUDIT_API_OPTS = {
    method: 'POST',

    headers: {
        'Content-Encoding': 'gzip',
        'Content-Type':     'application/json'
    }
};

const LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES = ['version', 'dev', 'requires', 'integrity'];

function readFile (filePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, (error, content) => {
            if (error)
                reject(error);
            else
                resolve(content);
        });
    });
}

function gzip (data) {
    return new Promise((resolve, reject) => {
        zlib.gzip(JSON.stringify(data), (error, compressedData) => {
            if (error)
                reject(error);
            else
                resolve(compressedData);
        });
    });
}

function getMetadata () {
    return {
        'node_version': process.version,
        'platform':     os.platform
    };
}

function filterTree (packageTree) {
    return mapValues(packageTree, packageInfo => {
        const requiredInfo = {};

        for (const requiredProperty of LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES) {
            if (requiredProperty in packageInfo)
                requiredInfo[requiredProperty] = packageInfo[requiredProperty];
        }

        if (packageInfo.dependencies)
            requiredInfo.dependencies = filterTree(packageInfo.dependencies);

        return requiredInfo;
    });
}

function getNpmLockDependencies (lockFileName) {
    return readFile(path.resolve(lockFileName))
        .then(lockFileContents => filterTree(JSON.parse(lockFileContents.toString()).dependencies));
}

function getAllDependencies () {
    return getNpmLockDependencies('package-lock.json')
        .catch(() => getNpmLockDependencies('npm-shrinkwrap.json'))
        .catch(() => {
            throw new Error('Failed to get locked dependencies from package-lock.json or npm-shrinkwrap.json!');
        });
}

function getAuditData () {
    const packageJsonPath = path.resolve('package.json');
    const packageJson     = require(packageJsonPath);
    const metadata        = getMetadata();

    return getAllDependencies(packageJsonPath, packageJson)
        .then(allDependencies => ({
            name:         packageJson.name,
            version:      packageJson.version,
            requires:     Object.assign({}, packageJson.devDependencies, packageJson.dependencies),
            dependencies: allDependencies,
            install:      [],
            remove:       [],
            metadata
        }));
}

function sendAuditDataToNPM (auditData) {
    return gzip(auditData)
        .then(compressedData => npmFetch(NPM_AUDIT_API_PATH, Object.assign({ body: compressedData }, NPM_AUDIT_API_OPTS)))
        .then(npmAuditResponse => npmAuditResponse.json());
}

module.exports = opts => {
    opts = opts || {};
    opts.reporter = opts.reporter || 'detail';

    return getAuditData()
        .then(auditData => sendAuditDataToNPM(auditData))
        .then(npmAuditResult => npmAuditReporter(npmAuditResult, opts));
};