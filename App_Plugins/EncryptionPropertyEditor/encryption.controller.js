angular.module("umbraco").controller("EncryptionController", function ($scope, $http) {
    var hash = $scope.model.config.hash;
    var salt = $scope.model.config.salt;

    var key = "diqrvfpi60uator62as5h88wxf0hn8d3daiam9k6ucyuidr4n2ajlwu2atp55uku";
    var IV = "mm8e1fqxmypbdqo7nvniusa6qitlcbxz";


    if ($scope.model.value.length > 0 && (hash === false || hash == 0)) {
        $http({
            method: "GET",
            url: "/umbraco/api/EncryptionApi/Decrypt?pw=ENCRYPTION-ACCESS&key=" + key + "&IV=" + IV + "&string_data=" + $scope.model.value,
            headers: { 'Content-Type': undefined },
            data: {}
        }).then(function (response) {
            if (response) {
                $scope.model.plaintext = response.data.replace(/"/g, "");
            } else {
                return false;
            }
        });
    }

    $scope.encrypt = function () {
        if (hash === true || hash == 1) {
            if ($scope.model.plaintext.length > 0) {
                $http({
                    method: "GET",
                    url: "/umbraco/api/EncryptionApi/Hash?pw=ENCRYPTION-ACCESS&password=" +
                        $scope.model.plaintext +
                        "&salt" +
                        salt,
                    headers: { 'Content-Type': undefined },
                    data: {}
                }).then(function (response) {
                    if (response) {
                        $scope.model.value = response.data.replace(/"/g, "");
                    } else {
                        return false;
                    }

                });
            } else {
                $scope.model.value = "";
            }
        } else {
            if ($scope.model.plaintext.length > 0) {
                $http({
                    method: "GET",
                    url: "/umbraco/api/EncryptionApi/Encrypt?pw=ENCRYPTION-ACCESS&key=" + key + "&IV=" + IV + "&string_data=" + $scope.model.plaintext,
                    headers: { 'Content-Type': undefined },
                    data: {}
                }).then(function (response) {

                    if (response) {
                        $scope.model.value = response.data.replace(/"/g, "");
                    } else {
                        return false;
                    }
                });

            } else {
                $scope.model.value = "";
            }
        }
    }
})