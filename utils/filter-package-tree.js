const { mapValues, pick } = require('lodash');


const LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES = ['version', 'dev', 'requires', 'integrity'];

module.exports = function filterTree (packageTree) {
    return mapValues(packageTree, packageInfo => {
        const requiredInfo = pick(packageInfo, LOCKED_DEPENDENCIES_REQUIRED_PROPERTIES);

        if (packageInfo.dependencies)
            requiredInfo.dependencies = filterTree(packageInfo.dependencies);

        return requiredInfo;
    });
}