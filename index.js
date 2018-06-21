const path             = require('path');
const fs               = require('fs');
const os               = require('os');
const zlib             = require('zlib');
const npmFetch         = require('npm-registry-fetch');
const npmAuditReporter = require('npm-audit-report');
const { mapValues, pick }    = require('lodash');
const resolveFrom = require('resolve-from');

const NPM_AUDIT_API_PATH = '/-/npm/v1/security/audits';

const NPM_AUDIT_API_OPTS = {
    method: 'POST',

    headers: {
        'Content-Encoding': 'gzip',
        'Content-Type':     'application/json'
    }
};

const LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES = ['version', 'dev', 'requires', 'integrity'];
const LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES_WITH_DEPS = LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES.concat('dependencies');


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
        const requiredInfo = pick(packageInfo, LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES);

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
        .catch(() => module.exports.scanInstalledDependencies())
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

module.exports.scanInstalledDependencies = () => {
    const packageJsonPath = path.resolve('package.json');
    const packageDir      = path.dirname(packageJsonPath);
    const packageNodeModules = path.join(packageDir, 'node_modules');
    const packageJson     = require(packageJsonPath);

    const isTopLevelDep = depPackageDir => depPackageDir.indexOf(packageDir) < 0 ||
                              path.dirname(depPackageDir) === packageNodeModules;

    const isLocalDep = (depPackageDir, parentPackageDir) => depPackageDir.indexOf(parentPackageDir) === 0;

    const topLevelDeps = {};
    const packageCache = {};

    let devFlag = false;

    function getDepPackageInfo (parentPackageDir, packageName, depsProp = 'dependencies') {
        const depPackageJsonPath = resolveFrom(parentPackageDir, `${packageName}/package.json`);

        if (!packageCache[depPackageJsonPath])
            packageCache[depPackageJsonPath] = collectDepPackageInfo(depPackageJsonPath, depsProp);

        return packageCache[depPackageJsonPath];
    }

    function collectDepPackageInfo (depPackageJsonPath, depsProp) {
        const depPackageDir = path.dirname(depPackageJsonPath);
        const depPackageJson = require(depPackageJsonPath);

        let requires     = null;
        let dependencies = null;

        if (depPackageJson[depsProp]) {
            const subDeps  = Object.keys(depPackageJson[depsProp]);
            const subDepsInfo = mapValues(depPackageJson[depsProp], (version, dep) => getDepPackageInfo(depPackageDir, dep));

            requires = mapValues(subDepsInfo, info => info.version);

            dependencies = {};

            for (const subDep of subDeps) {
                const subDepInfo = subDepsInfo[subDep];

                if (isLocalDep(subDepInfo.packageDir, depPackageDir))
                    dependencies[subDep] = pick(subDepInfo, LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES_WITH_DEPS);
                else if (isTopLevelDep(subDepInfo.packageDir) && !topLevelDeps[subDep])
                    topLevelDeps[subDep] = pick(subDepInfo, LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES_WITH_DEPS);
                else if (subDepInfo.packageDir.indexOf(packageDir) === 0) {
                    dependencies[subDep] = pick(subDepInfo, LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES_WITH_DEPS);
                }
            }

            if (Object.keys(dependencies).length === 0)
                dependencies = null;
        }

        const depPackageInfo = {
            packageDir: depPackageDir,
            version:    depPackageJson.version,
            integrity:  depPackageJson._integrity
        };

        if (devFlag)
            depPackageInfo.dev = true;

        if (requires)
            depPackageInfo.requires = requires;

        if (dependencies)
            depPackageInfo.dependencies = dependencies;

        return depPackageInfo;
    }

    Object.keys(packageJson.dependencies).forEach(dep => getDepPackageInfo(packageDir, dep));

    devFlag = true;

    Object.keys(packageJson.devDependencies).forEach(dep => getDepPackageInfo(packageDir, dep));

    return topLevelDeps;
};