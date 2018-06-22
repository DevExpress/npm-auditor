const path        = require('path');
const resolveFrom = require('resolve-from');
const filterTree  = require('./utils/filter-package-tree');

const { values, mapValues, zipObject, isEmpty } = require('lodash');


module.exports = class DependenciesScanner {
    constructor (rootPackageJsonPath) {
        this.rootPackageJsonPath = rootPackageJsonPath;
        this.rootPackageDir      = path.dirname(rootPackageJsonPath);

        this.packageCache = {};

        this.depsStack = [];

        this.scanFlags = { dev: false, useDevDeps: false };
    }

    _prepareRequires (depPackageInfo, dependencies) {
        let subDeps = Object.keys(dependencies);

        const optionalDeps = depPackageInfo.packageJson.optionalDependencies;

        if (optionalDeps)
            subDeps = subDeps.filter(subDep => !optionalDeps[subDep]);

        depPackageInfo.hasRequires  = true;

        Object.assign(depPackageInfo.requirePaths, zipObject(subDeps, subDeps.map(subDep => resolveFrom(depPackageInfo.packageDir, `${subDep}/package.json`))));

        for (const subDep of subDeps) {
            const subDepPackageJsonPath = depPackageInfo.requirePaths[subDep];

            let subDepParentPackageDir = subDepPackageJsonPath.indexOf(this.rootPackageDir) < 0
                ? this.rootPackageDir
                : path.dirname(path.dirname(path.dirname(subDepPackageJsonPath)));

            if (path.basename(subDepParentPackageDir) === 'node_modules')
                subDepParentPackageDir = path.dirname(subDepParentPackageDir);

            const subParentPackageJsonPath = path.join(subDepParentPackageDir, 'package.json');

            this.packageCache[subParentPackageJsonPath].hasDependencies = true;
            this.packageCache[subParentPackageJsonPath].dependenciesPaths[subDep] = subDepPackageJsonPath;
        }
    }

    _createDependencyInfo (depPackageJsonPath) {
        const depPackageDir  = path.dirname(depPackageJsonPath);
        const depPackageJson = require(depPackageJsonPath);

        const depPackageInfo = {
            packageDir:      depPackageDir,
            packageJsonPath: depPackageJsonPath,
            packageJson:     depPackageJson,

            version: depPackageJson.version,

            requirePaths: {},
            dependenciesPaths: {},
            hasRequires: false,
            hasDependencies: false
        };

        if (this.scanFlags.dev)
            depPackageInfo.dev = true;

        if (depPackageJson._integrity)
            depPackageInfo.integrity = depPackageJson._integrity;

        return depPackageInfo;
    }

    _getDependencyInfo (depPackageJsonPath) {
        let depPackageInfo = this.packageCache[depPackageJsonPath];

        if (depPackageInfo && !this.scanFlags.useDevDeps)
            return depPackageInfo;

        if (!depPackageInfo) {
            depPackageInfo = this._createDependencyInfo(depPackageJsonPath);

            this.packageCache[depPackageJsonPath] = depPackageInfo;
        }

        const subDependencies = this.scanFlags.useDevDeps
            ? depPackageInfo.packageJson.devDependencies
            : depPackageInfo.packageJson.dependencies;

        if (subDependencies && !isEmpty(subDependencies))
            this._prepareRequires(depPackageInfo, subDependencies);

        return depPackageInfo;
    }

    _processRequires (depPackageInfo) {
        const { dependenciesPaths, requirePaths } = depPackageInfo;

        if (depPackageInfo.hasRequires)
            depPackageInfo.requires = mapValues(requirePaths, requirePath => this.packageCache[requirePath].version);

        if (depPackageInfo.hasDependencies)
            depPackageInfo.dependencies = mapValues(dependenciesPaths, localSubDepPath => this.packageCache[localSubDepPath]);
    }

    _processDependency (depPackageJsonPath) {
        const packageInfo = this._getDependencyInfo(depPackageJsonPath);

        if (!packageInfo.hasRequires)
            return [];

        return values(packageInfo.requirePaths).filter(requirePath => !this.packageCache[requirePath]);
    }

    _scanPackageDependencies (getDevDeps) {
        this.scanFlags.dev        = !!getDevDeps;
        this.scanFlags.useDevDeps = !!getDevDeps;

        const depsStack = this._processDependency(this.rootPackageJsonPath);

        this.scanFlags.useDevDeps = false;

        while (depsStack.length)
            depsStack.push(...this._processDependency(depsStack.pop()));

        const packagesWithRequires = values(this.packageCache).filter(packageInfo => packageInfo.hasRequires);

        for (const depPackageInfo of packagesWithRequires)
            this._processRequires(depPackageInfo);
    }

    scan () {
        this._scanPackageDependencies();

        this._scanPackageDependencies(true);

        return filterTree(this.packageCache[this.rootPackageJsonPath].dependencies);
    }
}