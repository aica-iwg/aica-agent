(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["main"],{

/***/ 0:
/*!***************************!*\
  !*** multi ./src/main.ts ***!
  \***************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(/*! c:\repositories\cyst_visualization_2\src\main.ts */"zUnb");


/***/ }),

/***/ "AytR":
/*!*****************************************!*\
  !*** ./src/environments/environment.ts ***!
  \*****************************************/
/*! exports provided: environment */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "environment", function() { return environment; });
// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.
const environment = {
    production: false
};
/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
// import 'zone.js/dist/zone-error';  // Included with Angular CLI.


/***/ }),

/***/ "EilE":
/*!**********************************************!*\
  !*** ./src/app/network/network.component.ts ***!
  \**********************************************/
/*! exports provided: NetworkComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "NetworkComponent", function() { return NetworkComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "fXoL");
/* harmony import */ var _levels_service__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../levels.service */ "YnIV");
/* harmony import */ var _assets_Network_json__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../assets/Network.json */ "tjmI");
var _assets_Network_json__WEBPACK_IMPORTED_MODULE_2___namespace = /*#__PURE__*/__webpack_require__.t(/*! ../../assets/Network.json */ "tjmI", 1);
/* harmony import */ var _d3_svg_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../d3-svg.service */ "JC13");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/common/http */ "tk/3");
/* harmony import */ var _angular_common__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @angular/common */ "ofXK");







function NetworkComponent_button_15_Template(rf, ctx) { if (rf & 1) {
    const _r3 = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵgetCurrentView"]();
    _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](0, "button", 25);
    _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("click", function NetworkComponent_button_15_Template_button_click_0_listener() { _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵrestoreView"](_r3); const ctx_r2 = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵnextContext"](); return ctx_r2.simulateFromInput(); });
    _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](1, "Build");
    _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
} }
class NetworkComponent {
    constructor(http) {
        this.http = http;
        this.prov1 = false;
        this.prov2 = false;
        this.prov3 = false;
        this.Nodes = new Array();
        this.Dataset = new _angular_core__WEBPACK_IMPORTED_MODULE_0__["Input"]();
        this.IsPopped = false;
        this.d3 = new _d3_svg_service__WEBPACK_IMPORTED_MODULE_3__["D3SvgService"](innerHeight, innerWidth, this.http);
    }
    ngOnInit() {
        _assets_Network_json__WEBPACK_IMPORTED_MODULE_2__["network"].forEach(node => this.Nodes.push({ ID: node.id, connections: node.connections, type: node.Type, Ylevel: 0, Xlevel: 0, CardinalityFwd: 0 }));
        this.Nodes = Object(_levels_service__WEBPACK_IMPORTED_MODULE_1__["LevelNodes"])(this.Nodes);
        const Ylevels = Object(_levels_service__WEBPACK_IMPORTED_MODULE_1__["getMaxYLevel"])(this.Nodes);
        const Xlevels = Object(_levels_service__WEBPACK_IMPORTED_MODULE_1__["getMaxXlevel"])(this.Nodes);
        this.d3.AssignDataAndForce();
    }
    simulateFromInput() {
        this.checkInput();
        if (this.checkInput() === true) {
            this.d3.destroy();
            this.d3 = new _d3_svg_service__WEBPACK_IMPORTED_MODULE_3__["D3SvgService"](innerHeight, innerWidth, this.http);
            this.d3.AssignInputAndForce(this.Dataset);
        }
    }
    checkInput() {
        if (this.Dataset.network) {
            this.prov1 = true;
        }
        if (this.Dataset.messages) {
            this.prov3 = true;
        }
        if (this.Dataset.links) {
            this.prov2 = true;
        }
        if (!this.Dataset.links || !this.Dataset.messages || !this.Dataset.network) {
            return false;
        }
        return true;
    }
    onFileSelected(e) {
        this.prov1 = false;
        this.prov2 = false;
        this.prov3 = false;
        const inputNode = document.querySelector('#file');
        this.Dataset = new _angular_core__WEBPACK_IMPORTED_MODULE_0__["Input"]();
        if (typeof (FileReader) !== 'undefined') {
            for (const file of e.target.files) {
                const reader = new FileReader();
                reader.readAsText(file);
                reader.onload = (event) => {
                    const data = JSON.parse(event.target.result);
                    const name = file.name.toLowerCase();
                    if (name.match(`^(?!.*(nodes|messages|network)).*(links).*`)) {
                        this.Dataset.links = data;
                        console.log('data assigned - links');
                        return;
                    }
                    if (name.match(`^(?!.*(nodes|links|network)).*(messages).*`)) {
                        this.Dataset.messages = data;
                        console.log('data assigned - messages');
                        return;
                    }
                    if (name.match(`^(?!.*(messages|links)).*(nodes|network).*`)) {
                        this.Dataset.network = data;
                        console.log('data assigned - network');
                        return;
                    }
                };
            }
        }
    }
    CardUp() {
        const card = document.getElementById('card');
        const chevron = document.getElementById('chevron');
        if (!this.IsPopped) {
            card.classList.add('up');
            chevron.classList.add('up');
        }
        else {
            card.classList.remove('up');
            chevron.classList.remove('up');
        }
        this.IsPopped = !this.IsPopped;
    }
}
NetworkComponent.ɵfac = function NetworkComponent_Factory(t) { return new (t || NetworkComponent)(_angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵdirectiveInject"](_angular_common_http__WEBPACK_IMPORTED_MODULE_4__["HttpClient"])); };
NetworkComponent.ɵcmp = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵdefineComponent"]({ type: NetworkComponent, selectors: [["app-network"]], decls: 35, vars: 4, consts: [[1, "switch"], ["id", "bal", "type", "checkbox", "checked", "", 1, "input"], [1, "slider", "round"], ["width", "100vw", "height", "100vh"], ["id", "card", 1, "card"], ["id", "pad", 1, "pad"], ["id", "chevron", "src", "./../../assets/Images/chevron-down.svg", 1, "chevron", 3, "click"], [1, "section"], [1, "row"], [1, "col-md-6"], ["type", "button", 1, "button", 3, "click"], ["hidden", "", "type", "file", "name", "image", "id", "file", "multiple", "", 3, "change"], ["fileInput", ""], ["class", "button", "style", "position: absolute; left: auto;", 3, "click", 4, "ngIf"], [1, "container", "col-md-6", "provs"], ["type", "checkbox", "name", "prov1", "textContent", "Nodes Provided", "disabled", "", "value", "", 1, "check", 3, "checked", "checkedChange"], ["for", "prov1"], ["type", "checkbox", "name", "prov2", "textContent", "Links provided", "disabled", "", "value", "", 1, "check", 3, "checked", "checkedChange"], ["for", "prov2"], ["type", "checkbox", "name", "prov3", "textContent", "", "disabled", "", "value", "", 1, "check", 3, "checked", "checkedChange"], ["for", "prov3"], ["src", "./../../assets/Images/play.svg", "width", "30px", "height", "30px", "id", "simstart", 1, "play"], ["aria-hidden", "true", "src", "./../../assets/Images/play.svg", "width", "30px", "height", "30px", "id", "simplaypause", "hidden", "", 1, "play"], ["aria-hidden", "true", "src", "./../../assets/Images/stop.svg", "width", "30px", "height", "30px", "hidden", "", "id", "simstop", 1, "play"], ["id", "range", "type", "range", "min", "0", "max", "200", "value", "100"], [1, "button", 2, "position", "absolute", "left", "auto", 3, "click"]], template: function NetworkComponent_Template(rf, ctx) { if (rf & 1) {
        const _r4 = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵgetCurrentView"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](0, "label", 0);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](1, "input", 1);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](2, "span", 2);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵnamespaceSVG"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](3, "svg", 3);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵnamespaceHTML"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](4, "div", 4);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](5, "div", 5);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](6, "Simulation");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](7, "img", 6);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("click", function NetworkComponent_Template_img_click_7_listener() { return ctx.CardUp(); });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](8, "div", 7);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](9, "div", 8);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](10, "div", 9);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](11, "button", 10);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("click", function NetworkComponent_Template_button_click_11_listener() { _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵrestoreView"](_r4); const _r0 = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵreference"](14); return _r0.click(); });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](12, "Upload data");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](13, "input", 11, 12);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("change", function NetworkComponent_Template_input_change_13_listener($event) { return ctx.onFileSelected($event); });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtemplate"](15, NetworkComponent_button_15_Template, 2, 0, "button", 13);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](16, "div", 14);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](17, "input", 15);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("checkedChange", function NetworkComponent_Template_input_checkedChange_17_listener($event) { return ctx.prov1 = $event; });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](18, "label", 16);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](19, " Nodes provided");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](20, "br");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](21, "input", 17);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("checkedChange", function NetworkComponent_Template_input_checkedChange_21_listener($event) { return ctx.prov2 = $event; });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](22, "label", 18);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](23, " Links provided");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](24, "br");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](25, "input", 19);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵlistener"]("checkedChange", function NetworkComponent_Template_input_checkedChange_25_listener($event) { return ctx.prov3 = $event; });
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](26, "label", 20);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](27, " Messages provided");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](28, "div", 7);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](29, "img", 21);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](30, "img", 22);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](31, "img", 23);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementStart"](32, "div", 7);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵtext"](33, " Simulation speed:\n");
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](34, "input", 24);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelementEnd"]();
    } if (rf & 2) {
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵadvance"](15);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵproperty"]("ngIf", ctx.checkInput() === true);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵadvance"](2);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵproperty"]("checked", ctx.prov1);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵadvance"](4);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵproperty"]("checked", ctx.prov2);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵadvance"](4);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵproperty"]("checked", ctx.prov3);
    } }, directives: [_angular_common__WEBPACK_IMPORTED_MODULE_5__["NgIf"]], styles: [".links[_ngcontent-%COMP%]   line[_ngcontent-%COMP%] {\n  stroke: #3a0a0a;\n  stroke-opacity: 0.6;\n}\n.nodes[_ngcontent-%COMP%]   circle[_ngcontent-%COMP%] {\n  stroke: #fff;\n  fill: #3a0a0a;\n  stroke-width: 1.5px;\n}\n.check[_ngcontent-%COMP%] {\n  margin: 2px;\n  background-color: #9E0E0E;\n}\n.provs[_ngcontent-%COMP%] {\n  margin: auto;\n  vertical-align: middle;\n  font-size: 15px;\n}\n.button[_ngcontent-%COMP%] {\n  background-color: #555555;\n  border: none;\n  color: white;\n  padding: 10px 10px;\n  text-align: center;\n  text-decoration: none;\n  display: inline-block;\n  font-size: 16px;\n  margin: 4px 2px;\n  cursor: pointer;\n}\n.switch[_ngcontent-%COMP%] {\n  font-family: Arial, Helvetica, sans-serif;\n  position: absolute;\n  top: 30px;\n  display: inline-block;\n  width: 60px;\n  height: 34px;\n}\n\n.slider[_ngcontent-%COMP%] {\n  position: absolute;\n  cursor: pointer;\n  top: 0;\n  left: 0;\n  right: 0;\n  bottom: 0;\n  background-color: #ccc;\n  transition: 0.4s;\n  align-content: center;\n}\n.slider[_ngcontent-%COMP%]::after {\n  align-content: center;\n  position: absolute;\n  content: \"Balance\";\n  transform: translateY(-20px);\n}\n.slider[_ngcontent-%COMP%]:before {\n  position: absolute;\n  content: \"\";\n  height: 26px;\n  width: 26px;\n  left: 4px;\n  bottom: 4px;\n  background-color: white;\n  transition: 0.4s;\n}\n.input[_ngcontent-%COMP%]:checked    + .slider[_ngcontent-%COMP%] {\n  background-color: #0d223f;\n}\n.input[_ngcontent-%COMP%]:focus    + .slider[_ngcontent-%COMP%] {\n  box-shadow: 0 0 1px #0d223f;\n}\n.input[_ngcontent-%COMP%]:checked    + .slider[_ngcontent-%COMP%]:before {\n  transform: translateX(26px);\n  content: \"\";\n}\n\n.slider.round[_ngcontent-%COMP%] {\n  border-radius: 34px;\n}\n.slider.round[_ngcontent-%COMP%]:before {\n  border-radius: 50%;\n}\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5ldHdvcmsuY29tcG9uZW50Lmxlc3MiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQ0E7RUFDRSxlQUFBO0VBQ0EsbUJBQUE7QUFBRjtBQUdBO0VBQ0UsWUFBQTtFQUNBLGFBQUE7RUFDQSxtQkFBQTtBQURGO0FBR0E7RUFDRSxXQUFBO0VBQ0EseUJBQUE7QUFERjtBQUlBO0VBQ0UsWUFBQTtFQUNBLHNCQUFBO0VBQ0EsZUFBQTtBQUZGO0FBSUE7RUFDRSx5QkFBQTtFQUNBLFlBQUE7RUFDQSxZQUFBO0VBQ0Esa0JBQUE7RUFDQSxrQkFBQTtFQUNBLHFCQUFBO0VBQ0EscUJBQUE7RUFDQSxlQUFBO0VBQ0EsZUFBQTtFQUNBLGVBQUE7QUFGRjtBQUlBO0VBQ0UseUNBQUE7RUFDQSxrQkFBQTtFQUNBLFNBQUE7RUFDQSxxQkFBQTtFQUNBLFdBQUE7RUFDQSxZQUFBO0FBRkY7QUFDQSxlQUFlO0FBSWY7RUFDRSxrQkFBQTtFQUNBLGVBQUE7RUFDQSxNQUFBO0VBQ0EsT0FBQTtFQUNBLFFBQUE7RUFDQSxTQUFBO0VBQ0Esc0JBQUE7RUFFQSxnQkFBQTtFQUNBLHFCQUFBO0FBRkY7QUFJQTtFQUNFLHFCQUFBO0VBQ0Esa0JBQUE7RUFDQSxrQkFBQTtFQUNBLDRCQUFBO0FBRkY7QUFJQTtFQUNFLGtCQUFBO0VBQ0EsV0FBQTtFQUNBLFlBQUE7RUFDQSxXQUFBO0VBQ0EsU0FBQTtFQUNBLFdBQUE7RUFDQSx1QkFBQTtFQUVBLGdCQUFBO0FBRkY7QUFLQTtFQUNFLHlCQUFBO0FBSEY7QUFNQTtFQUNFLDJCQUFBO0FBSkY7QUFPQTtFQUdFLDJCQUFBO0VBQ0EsV0FBQTtBQUxGO0FBQ0Esb0JBQW9CO0FBUXBCO0VBQ0UsbUJBQUE7QUFORjtBQVNBO0VBQ0Usa0JBQUE7QUFQRiIsImZpbGUiOiJuZXR3b3JrLmNvbXBvbmVudC5sZXNzIiwic291cmNlc0NvbnRlbnQiOlsiQGJncmVlbjojMGQyMjNmO1xuLmxpbmtzIGxpbmUge1xuICBzdHJva2U6IHJnYig1OCwgMTAsIDEwKTtcbiAgc3Ryb2tlLW9wYWNpdHk6IDAuNjtcbn1cblxuLm5vZGVzIGNpcmNsZSB7XG4gIHN0cm9rZTogI2ZmZjtcbiAgZmlsbDogcmdiKDU4LCAxMCwgMTApO1xuICBzdHJva2Utd2lkdGg6IDEuNXB4O1xufVxuLmNoZWNre1xuICBtYXJnaW46MnB4O1xuICBiYWNrZ3JvdW5kLWNvbG9yOiAjOUUwRTBFO1xuXG59XG4ucHJvdnN7XG4gIG1hcmdpbjogYXV0bztcbiAgdmVydGljYWwtYWxpZ246bWlkZGxlO1xuICBmb250LXNpemU6IDE1cHg7XG59XG4uYnV0dG9uIHtcbiAgYmFja2dyb3VuZC1jb2xvcjogIzU1NTU1NTtcbiAgYm9yZGVyOiBub25lO1xuICBjb2xvcjogd2hpdGU7XG4gIHBhZGRpbmc6IDEwcHggMTBweDtcbiAgdGV4dC1hbGlnbjogY2VudGVyO1xuICB0ZXh0LWRlY29yYXRpb246IG5vbmU7XG4gIGRpc3BsYXk6IGlubGluZS1ibG9jaztcbiAgZm9udC1zaXplOiAxNnB4O1xuICBtYXJnaW46IDRweCAycHg7XG4gIGN1cnNvcjogcG9pbnRlcjtcbn1cbi5zd2l0Y2gge1xuICBmb250LWZhbWlseTogQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZjtcbiAgcG9zaXRpb246IGFic29sdXRlO1xuICB0b3A6MzBweDtcbiAgZGlzcGxheTogaW5saW5lLWJsb2NrO1xuICB3aWR0aDogNjBweDtcbiAgaGVpZ2h0OiAzNHB4O1xufVxuLyogVGhlIHNsaWRlciAqL1xuLnNsaWRlciB7XG4gIHBvc2l0aW9uOiBhYnNvbHV0ZTtcbiAgY3Vyc29yOiBwb2ludGVyO1xuICB0b3A6IDA7XG4gIGxlZnQ6IDA7XG4gIHJpZ2h0OiAwO1xuICBib3R0b206IDA7XG4gIGJhY2tncm91bmQtY29sb3I6ICNjY2M7XG4gIC13ZWJraXQtdHJhbnNpdGlvbjogLjRzO1xuICB0cmFuc2l0aW9uOiAuNHM7XG4gIGFsaWduLWNvbnRlbnQ6IGNlbnRlcjtcbn1cbi5zbGlkZXI6OmFmdGVye1xuICBhbGlnbi1jb250ZW50OiBjZW50ZXI7XG4gIHBvc2l0aW9uOmFic29sdXRlO1xuICBjb250ZW50OiBcIkJhbGFuY2VcIjtcbiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC0yMHB4KVxufVxuLnNsaWRlcjpiZWZvcmUge1xuICBwb3NpdGlvbjogYWJzb2x1dGU7XG4gIGNvbnRlbnQ6IFwiXCI7XG4gIGhlaWdodDogMjZweDtcbiAgd2lkdGg6IDI2cHg7XG4gIGxlZnQ6IDRweDtcbiAgYm90dG9tOiA0cHg7XG4gIGJhY2tncm91bmQtY29sb3I6IHdoaXRlO1xuICAtd2Via2l0LXRyYW5zaXRpb246IC40cztcbiAgdHJhbnNpdGlvbjogLjRzO1xufVxuXG4uaW5wdXQ6Y2hlY2tlZCArIC5zbGlkZXIge1xuICBiYWNrZ3JvdW5kLWNvbG9yOiBAYmdyZWVuO1xufVxuXG4uaW5wdXQ6Zm9jdXMgKyAuc2xpZGVyIHtcbiAgYm94LXNoYWRvdzogMCAwIDFweCBAYmdyZWVuO1xufVxuXG4uaW5wdXQ6Y2hlY2tlZCArIC5zbGlkZXI6YmVmb3JlIHtcbiAgLXdlYmtpdC10cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMjZweCk7XG4gIC1tcy10cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMjZweCk7XG4gIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgyNnB4KTtcbiAgY29udGVudDpcIlwiXG59XG5cbi8qIFJvdW5kZWQgc2xpZGVycyAqL1xuLnNsaWRlci5yb3VuZCB7XG4gIGJvcmRlci1yYWRpdXM6IDM0cHg7XG59XG5cbi5zbGlkZXIucm91bmQ6YmVmb3JlIHtcbiAgYm9yZGVyLXJhZGl1czogNTAlO1xufVxuXG5cblxuIl19 */"] });


/***/ }),

/***/ "JC13":
/*!***********************************!*\
  !*** ./src/app/d3-svg.service.ts ***!
  \***********************************/
/*! exports provided: D3SvgService, tooltipClass */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "D3SvgService", function() { return D3SvgService; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "tooltipClass", function() { return tooltipClass; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "mrSG");
/* harmony import */ var d3__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! d3 */ "VphZ");
/* harmony import */ var _svg_pattern_service__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./svg-pattern.service */ "VieR");
/* harmony import */ var _cansvas_class_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./cansvas-class.service */ "WWS1");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/core */ "fXoL");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @angular/common/http */ "tk/3");






class D3SvgService {
    constructor(height, width, http) {
        this.height = height;
        this.width = width;
        this.http = http;
        /**
         * @brief vytváří force layout pro vizualizaci sítě
         * @param graph soubor Nodů a linek
         */
        this.simState = 'stopped';
    }
    /**
     * @param Links objekty přebírané z Links.json
     * @returns array spojení podle popisu z Network.json
     */
    AssignLinks(Links) {
        const links = new Array();
        Links.Links.forEach(link => {
            links.push({ source: link.src, target: link.dest, messages: { Requests: [], Responses: [] } });
        });
        return links;
    }
    AssignMessages(response) {
        const Requests = new Array();
        const Responses = new Array();
        response.messages.forEach(message => (message.Type === 'REQUEST') ? Requests.push(message) : Responses.push(message));
        Requests.sort((a, b) => a.timestamp - b.timestamp);
        Responses.sort((a, b) => a.timestamp - b.timestamp);
        return { Requests, Responses };
    }
    /**
     *
     * @param Nodes objekty přebírané z Network.json
     * @returns array uzlů podle popisu z Network.json
     */
    AssignNodes(Nodes) {
        const nodes = new Array();
        Nodes.network.forEach(node => {
            nodes.push({ name: node.id, type: node.Type, services: node === null || node === void 0 ? void 0 : node.services, fixated: false });
        });
        return nodes;
    }
    /**
     * @brief kontrola načtení dat z API do proměnné graph
     * @param graph údaje o grafu(Links, Nodes)
     * @returns graph
     */
    GraphPms(graph) {
        return new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                if (graph && graph.links && graph.nodes) {
                    console.log('Graph: success', graph);
                    resolve(graph);
                    clearInterval(interval);
                }
                else {
                    console.log('failed');
                }
            }, 100);
        });
    }
    /**
     * @brief kontrola přijmu dat z API
     * @param response subscribe pro Links.json nebo Network.json
     * @returns promise response
     */
    GetDataPms(response) {
        return new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                if (response) {
                    resolve(response);
                    clearInterval(interval);
                }
                else {
                    console.log('Data fetch failed');
                }
            }, 500);
        });
    }
    /**
     * @brief přebírá data z API a přepisuje do graph
     */
    AssignInputAndForce(data) {
        const graph = {};
        graph.links = this.AssignLinks(data.links);
        graph.messages = this.AssignMessages(data.messages);
        graph.nodes = this.AssignNodes(data.network);
        this.GraphPms(graph).then(res => this.Force(res));
    }
    AssignDataAndForce() {
        const graph = {};
        const urls = [
            { id: 0, path: './assets/Links.json' },
            { id: 1, path: './assets/Network.json' },
            { id: 2, path: './assets/messages.json' }
        ];
        urls.forEach(url => {
            this.http.get(url.path).subscribe((response) => Object(tslib__WEBPACK_IMPORTED_MODULE_0__["__awaiter"])(this, void 0, void 0, function* () {
                yield this.GetDataPms(response);
                switch (url.id) {
                    case 0:
                        graph.links = this.AssignLinks(response);
                        break;
                    case 1:
                        graph.nodes = this.AssignNodes(response);
                        break;
                    case 2:
                        graph.messages = this.AssignMessages(response);
                        this.Force(yield this.GraphPms(graph));
                        break;
                }
            }));
        });
    }
    destroy() {
        document.querySelector('#simstop').click();
        d3__WEBPACK_IMPORTED_MODULE_1__["select"]('svg').selectAll('*').remove();
    }
    Force(graph) {
        let cvs = null;
        const Sim = document.querySelector('#simstart');
        const pause = document.querySelector('#simplaypause');
        const stop = document.querySelector('#simstop');
        const balance = document.getElementById('bal');
        balance.addEventListener('change', change);
        Sim.addEventListener('click', () => {
            this.simState = 'running';
            cvs = new _cansvas_class_service__WEBPACK_IMPORTED_MODULE_3__["Canvas"](graph);
            stop.removeAttribute('hidden');
            pause.removeAttribute('hidden');
            Sim.src = './../../assets/Images/restart.svg';
        });
        pause.addEventListener('click', () => {
            if (this.simState === 'running') {
                cvs.pauseSimulation();
                this.simState = 'paused';
                pause.src = './../../assets/Images/pause.svg';
            }
            else {
                cvs.resumeSimulation();
                this.simState = 'running';
                pause.src = './../../assets/Images/play.svg';
            }
        });
        stop.addEventListener('click', () => {
            this.simState = 'stopped';
            cvs.stopSimulation();
            stop.setAttribute('hidden', true);
            pause.setAttribute('hidden', true);
            Sim.src = './../../assets/Images/play.svg';
        });
        const svg = d3__WEBPACK_IMPORTED_MODULE_1__["select"]('svg');
        const r = 40;
        const tooltip = new tooltipClass(graph, r);
        const simulation = d3__WEBPACK_IMPORTED_MODULE_1__["forceSimulation"](graph.nodes)
            .force('link', d3__WEBPACK_IMPORTED_MODULE_1__["forceLink"]()
            .id((d) => d.name)
            .links(graph.links))
            .force('collide', d3__WEBPACK_IMPORTED_MODULE_1__["forceCollide"](r * 1.5))
            .force('charge', d3__WEBPACK_IMPORTED_MODULE_1__["forceManyBody"]().strength(-40))
            .on('tick', ticked);
        Object(_svg_pattern_service__WEBPACK_IMPORTED_MODULE_2__["SvgDefs"])(svg);
        const link = svg
            .append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(graph.links)
            .enter()
            .append('line')
            .attr('stroke-width', (d) => 1)
            .attr('stroke', (d) => 'black');
        const linkOverlay = svg
            .append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(graph.links)
            .enter()
            .append('line')
            .attr('stroke-width', (d) => 30)
            .attr('stroke', (d) => 'transparent')
            .style('position', 'absolute')
            .style('z-index', '20')
            .on('mouseenter', (e, d) => { if (!tooltip.isTooltipHidden && !tooltip.On) {
            tooltip.MsgTooltipHover(e, d);
        } })
            .on('mouseleave', () => tooltip.TooltipHidden())
            .on('click', () => tooltip.On = !tooltip.On);
        const node = svg
            .append('g')
            .attr('class', 'nodes')
            .selectAll('circle')
            .data(graph.nodes)
            .enter()
            .append('circle')
            .attr('r', r)
            .attr('fill', (d) => `url(#${d.type})`)
            .on('dblclick', dblclick)
            .on('mouseenter', (e, d) => { if (!tooltip.isTooltipHidden) {
            tooltip.TooltipHover(e, d);
        } })
            .on('mouseleave', () => tooltip.TooltipHidden())
            .call(d3__WEBPACK_IMPORTED_MODULE_1__["drag"]()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
        const label = svg.selectAll(null)
            .data(graph.nodes)
            .enter()
            .append('text')
            .text((d) => d.name)
            .style('text-anchor', 'middle')
            .style('fill', '#555')
            .style('font-family', 'Arial')
            .style('font-size', 12);
        /**
         * @brief vytvoří okénko s informaci o jednotlivých nodech
         * @param node uzel, pro který se má tooltip objevit
         */
        /**
         * @brief zobrazí tooltip
         * @param event vyvolaná interakcí uživatele
         * @param node uzel, pro který je událost vyvolaná
         * @returns styly pro tooltip (průhlednost, z-index a pozici xy)
         */
        /**
         * @brief schová tooltip
         * @returns styly pro tooltip (průhlednost 100%, přenese do pozadí)
         */
        function change() {
            if (!balance.checked) {
                graph.nodes.forEach(n => {
                    d3__WEBPACK_IMPORTED_MODULE_1__["select"](this).classed('fixed', n.fixed = true);
                    n.fx = n.x;
                    n.fy = n.y;
                });
            }
            else {
                graph.nodes.forEach(n => {
                    if (!n.fixated) {
                        d3__WEBPACK_IMPORTED_MODULE_1__["select"](this).classed('fixed', n.fixed = false);
                        n.fx = null;
                        n.fy = null;
                    }
                });
            }
        }
        /**
         * @brief ticky grafu
         */
        function ticked() {
            node
                .attr('cx', (d) => d.x = Math.max(r, Math.min(innerWidth - r, d.x)))
                .attr('cy', (d) => d.y = Math.max(r, Math.min(innerHeight - r, d.y)));
            link
                .attr('x1', (d) => d.source.x)
                .attr('y1', (d) => d.source.y)
                .attr('x2', (d) => d.target.x)
                .attr('y2', (d) => d.target.y);
            linkOverlay
                .attr('x1', (d) => d.source.x)
                .attr('y1', (d) => d.source.y)
                .attr('x2', (d) => d.target.x)
                .attr('y2', (d) => d.target.y);
            label.attr('x', (d) => d.x)
                .attr('y', (d) => d.y - (r + 10));
        }
        /**
         * @brief příprava na drag
         * @param event event vyvolaný uživatelem na svg objektu
         * @param d uzel na kterém byl event vyvolaný
         */
        function dragstarted(event, d) {
            if (!event.active) {
                simulation.alphaTarget(0.3).restart();
            }
            d3__WEBPACK_IMPORTED_MODULE_1__["select"](this).classed('fixed', d.fixed = true);
            tooltip.TooltipHidden();
            d.fixated = true;
            tooltip.isTooltipHidden = true;
            tooltip.On = false;
        }
        /**
         * @brief mění pozici nodů v závislosti na pohybu a pozici myši
         */
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        /**
         * @brief konec tažení
         */
        function dragended(event, d) {
            if (!event.active) {
                simulation.alphaTarget(0);
            }
            tooltip.isTooltipHidden = false;
        }
        /**
         * @brief uvolňuje připnutý node
         */
        function dblclick(event, d) {
            if (!balance.checked) {
                return;
            }
            d.fixated = false;
            d3__WEBPACK_IMPORTED_MODULE_1__["select"](this).classed('fixed', d.fixed = false);
            d.fx = null;
            d.fy = null;
        }
    }
}
D3SvgService.ɵfac = function D3SvgService_Factory(t) { _angular_core__WEBPACK_IMPORTED_MODULE_4__["ɵɵinvalidFactory"](); };
D3SvgService.ɵprov = _angular_core__WEBPACK_IMPORTED_MODULE_4__["ɵɵdefineInjectable"]({ token: D3SvgService, factory: D3SvgService.ɵfac, providedIn: 'any' });
class tooltipClass {
    constructor(graph, r) {
        this.graph = graph;
        this.r = r;
        this.messageKeys = [
            'ID',
            'Type',
            'Origin',
            'Source',
            'Target',
            'Destination service',
            'Source service',
            'Action',
            'Session',
            'Authorization',
            'timestamp',
        ];
        this.RRs = null;
        this.RRsCheck = false;
        this.isTooltipHidden = false;
        this.On = false;
        this.linkref = null;
        this.tooltip = d3__WEBPACK_IMPORTED_MODULE_1__["select"]('body')
            .append('div')
            .attr('class', 'tooltip')
            .style('position', 'absolute')
            .style('padding', '10px')
            .style('z-index', '10')
            .style('min-width', '150px')
            .style('min-height', '50px')
            .style('background-color', 'rgba(32, 32, 60, 0.8)')
            .style('color', 'silver')
            .style('border-radius', '5px')
            .style('opacity', '0')
            .style('transition:', 'opacity 0.3s linear')
            .text('')
            .on('dblclick', () => {
            this.On = false;
            return this.TooltipHidden();
        });
    }
    TooltipHidden() {
        if (!this.On) {
            this.linkref = null;
            this.tooltip.style('opacity', '0').style('z-index', '-10');
        }
    }
    loadTooltipContent(node) {
        var _a;
        let htmlContent = '<div>';
        htmlContent += '<span class="name"> Node: ' + node.name + '<\/span><br>';
        htmlContent += '<span class="service">Services:<\/span><hr>';
        (_a = node.services) === null || _a === void 0 ? void 0 : _a.forEach(service => {
            Object.keys(service).forEach(key => htmlContent += '<b>' + key + ': <\/b>' + service[key] + ' ');
            htmlContent += '<hr>';
        });
        htmlContent += '<\/div>';
        this.tooltip.html(htmlContent);
    }
    MsgTooltipHover(event, link) {
        if (!this.isTooltipHidden && !this.On) {
            this.linkref = link;
            this.loadMsgTooltip(link);
            this.tooltip
                .style('top', event.clientY + 'px')
                .style('left', event.clientX + 10 + 'px')
                .style('opacity', '100')
                .style('z-index', '10');
        }
    }
    loadMsgTooltip(link) {
        let htmlContent = `<label class="switch"><input id="RRS" type="checkbox" ${this.RRsCheck ? 'checked' : ''} ><span class="RRs"><\/span><\/label><br>`;
        htmlContent += `<span class="service" id="${link.source.name + link.target.name}">Intercepted communication: <\/span><hr>`;
        const Type = this.RRsCheck ? 'Responses' : 'Requests';
        if (link.messages[Type].length === 0) {
            link.messages[Type] = this.graph.messages[Type].filter(item => (Object.values(link.source).includes(item.Source) || (Object.values(link.target).includes(item.Source)))
                &&
                    (Object.values(link.source).includes(item.target) || (Object.values(link.target).includes(item.Source))));
        }
        const activemessages = link.messages[Type].filter(message => message.timestamp <= this.graph.messages.currentTimestamp &&
            message.timestamp >= this.graph.messages.currentTimestamp - 5);
        this.messageKeys
            .forEach(key => {
            let active = activemessages[activemessages.length - 1];
            if (active) {
                active = active[key];
            }
            else {
                active = '';
            }
            htmlContent += `<b>${key}: <\/b> <span id=${key.replace(' ', '_')}>${active}<\/span><br>`;
        });
        htmlContent += '<hr>';
        htmlContent += '<hr>';
        htmlContent += '<\/div>';
        this.tooltip.html(htmlContent);
        this.RRs = document.getElementById('RRS');
        this.RRs.checked = this.RRsCheck;
        this.RRs.addEventListener('change', () => {
            this.RRsCheck = this.RRsCheck ? false : true;
            this.loadMsgTooltip(link);
        });
    }
    TooltipHover(event, node) {
        if (!this.isTooltipHidden && !this.On) {
            this.loadTooltipContent(node);
        }
        this.tooltip.style('top', (node.y - 10) + 'px').style('left', (node.x + this.r + 10) + 'px').style('opacity', '100').style('z-index', '10');
    }
    runSimulation() {
        this.simulation = 'run';
        console.log(this.simulation);
    }
    stopSimulation() {
        this.simulation = 'stop';
        console.log(this.simulation);
    }
    pauseSimulation() {
        this.simulation = 'paused';
        console.log(this.simulation);
    }
}


/***/ }),

/***/ "Sy1n":
/*!**********************************!*\
  !*** ./src/app/app.component.ts ***!
  \**********************************/
/*! exports provided: AppComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AppComponent", function() { return AppComponent; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "fXoL");
/* harmony import */ var _network_network_component__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./network/network.component */ "EilE");


/**
 * řešení a vše důležité naleznete v souboru d3-svg.service.ts
 *
**/
class AppComponent {
    constructor() {
        this.title = 'NWCAVis';
    }
}
AppComponent.ɵfac = function AppComponent_Factory(t) { return new (t || AppComponent)(); };
AppComponent.ɵcmp = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵdefineComponent"]({ type: AppComponent, selectors: [["app-root"]], decls: 2, vars: 0, consts: [["id", "canvas"]], template: function AppComponent_Template(rf, ctx) { if (rf & 1) {
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](0, "canvas", 0);
        _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵelement"](1, "app-network");
    } }, directives: [_network_network_component__WEBPACK_IMPORTED_MODULE_1__["NetworkComponent"]], styles: ["body[_ngcontent-%COMP%] {\n  margin: 0;\n  padding: 0;\n}\ncanvas[_ngcontent-%COMP%] {\n  margin: 0;\n  padding: 0;\n  position: absolute;\n  left: 0;\n  top: 0;\n  z-index: -1;\n  width: 100vw;\n  height: 100vh;\n}\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5jb21wb25lbnQubGVzcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtFQUNFLFNBQUE7RUFDQSxVQUFBO0FBQ0Y7QUFDQTtFQUNFLFNBQUE7RUFDQSxVQUFBO0VBQ0Esa0JBQUE7RUFDQSxPQUFBO0VBQ0EsTUFBQTtFQUNBLFdBQUE7RUFDQSxZQUFBO0VBQ0EsYUFBQTtBQUNGIiwiZmlsZSI6ImFwcC5jb21wb25lbnQubGVzcyIsInNvdXJjZXNDb250ZW50IjpbImJvZHl7XG4gIG1hcmdpbjogMDtcbiAgcGFkZGluZzogMDtcbn1cbmNhbnZhc3tcbiAgbWFyZ2luOiAwO1xuICBwYWRkaW5nOiAwO1xuICBwb3NpdGlvbjogYWJzb2x1dGU7XG4gIGxlZnQ6IDA7XG4gIHRvcDogMDtcbiAgei1pbmRleDogLTE7XG4gIHdpZHRoOiAxMDB2dztcbiAgaGVpZ2h0OiAxMDB2aDtcbn1cbiJdfQ== */"] });


/***/ }),

/***/ "VieR":
/*!****************************************!*\
  !*** ./src/app/svg-pattern.service.ts ***!
  \****************************************/
/*! exports provided: SvgDefs */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SvgDefs", function() { return SvgDefs; });
/**
 * @brief přidává svg "šablony" pro různá zařízení
 * @param svg svg (graf,...)
 */
function SvgDefs(svg) {
    const defs = svg.append('svg:defs');
    const devices = [
        'end-device-clear',
        'end-device-firewall-clear',
        'end-device-fraud',
        'end-device-firewall-fraud',
        'router-clear',
        'router-firewall-clear',
        'router-fraud',
        'router-firewall-fraud',
    ];
    devices.forEach(device => {
        defs.append('svg:pattern')
            .attr('id', device)
            .attr('width', '100%')
            .attr('height', '100%')
            .attr('patternContentUnits', 'objectBoundingBox')
            .append('svg:image')
            .attr('width', 1)
            .attr('height', 1)
            .attr('preserveAspectRatio', 'none')
            .attr('xlink:href', 'assets/Images/' + device + '.svg');
    });
}


/***/ }),

/***/ "WWS1":
/*!******************************************!*\
  !*** ./src/app/cansvas-class.service.ts ***!
  \******************************************/
/*! exports provided: Canvas */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Canvas", function() { return Canvas; });
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/core */ "fXoL");

// tslint:disable: no-bitwise
let stop = 0;
let pause = 1;
class Canvas {
    constructor(graph) {
        this.graph = graph;
        this.pause = 1;
        this.stop = 0;
        this.Init();
    }
    updateInfo(message) {
        var _a;
        const obj = (_a = (document.querySelector(`#${message.Target + message.Source}`))) !== null && _a !== void 0 ? _a : (document.querySelector(`#${message.Source + message.Target}`));
        if (!obj) {
            return;
        }
        const RR = document.querySelector('#RRS');
        if (!RR) {
            console.log('no RR');
            return;
        }
        else if ((!RR.checked && message.Type === 'RESPONSE') || (RR.checked && message.Type === 'REQUEST')) {
            console.log('Bad Type');
            return;
        }
        Object.keys(message).forEach(key => {
            const element = document.querySelector(`#${key.replace(' ', '_')}`);
            if (element) {
                element.innerHTML = message[key];
            }
        });
    }
    pauseSimulation() {
        pause = 0;
        this.pause = 0;
        console.log(pause);
    }
    resumeSimulation() {
        pause = 1;
        this.pause = 1;
        console.log('resume');
    }
    stopSimulation() {
        console.log('stopped');
        this.stop = 1;
        stop = 1;
        console.log(stop);
    }
    Init() {
        const STEPSPERSECOND = 10;
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        const acceleration = document.getElementById('range');
        canvas.width = innerWidth;
        canvas.height = innerHeight;
        window.addEventListener('resize', () => {
            canvas.width = innerWidth;
            canvas.height = innerHeight;
        });
        let ParticleArray = [];
        const messages = this.graph.messages.Requests.concat(this.graph.messages.Responses);
        messages.sort((a, b) => (a === null || a === void 0 ? void 0 : a.timestamp) - (b === null || b === void 0 ? void 0 : b.timestamp));
        console.log(messages);
        let i = 0;
        let currentTimestamp = messages[0].timestamp;
        let lastUpdateTime = Date.now();
        let currentUpdateTime;
        const interval2 = setInterval(() => {
            var _a, _b;
            if (stop === 1) {
                ParticleArray = [];
                clearInterval(interval2);
                stop = 0;
                return;
            }
            currentUpdateTime = Date.now();
            if (this.pause === 1) {
                currentTimestamp += (_a = (currentUpdateTime - lastUpdateTime) / (1000 / STEPSPERSECOND * 100) * Number(acceleration.value)) !== null && _a !== void 0 ? _a : 0;
            }
            else {
                currentTimestamp += 0;
            }
            if (i === messages.length) {
                clearInterval(interval2);
            }
            else {
                if (messages[i].timestamp < currentTimestamp && Number(acceleration.value) !== 0) {
                    this.graph.messages.currentTimestamp = messages[i].timestamp;
                    const source = this.graph.nodes.find(suspect => suspect.name === messages[i].Source);
                    const target = this.graph.nodes.find(suspect => suspect.name === messages[i].Target);
                    ParticleArray.push(new Particle(source.x, source.y, 5, ((_b = messages[i]) === null || _b === void 0 ? void 0 : _b.Type) === 'REQUEST' ? 'red' : 'blue', source, target));
                    i++;
                    this.updateInfo(messages[i]);
                }
            }
            lastUpdateTime = currentUpdateTime;
        }, 10);
        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ParticleArray = ParticleArray.filter(particle => (particle.pathProgress < 1));
            ParticleArray.forEach(particle => {
                particle.update();
                particle.draw();
            });
            requestAnimationFrame(animate);
        }
        animate();
    }
}
Canvas.ɵfac = function Canvas_Factory(t) { _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵinvalidFactory"](); };
Canvas.ɵprov = _angular_core__WEBPACK_IMPORTED_MODULE_0__["ɵɵdefineInjectable"]({ token: Canvas, factory: Canvas.ɵfac, providedIn: 'root' });
class Particle {
    constructor(x, y, size, color, srcNode, tgtNode) {
        this.x = x;
        this.y = y;
        this.size = size;
        this.color = color;
        this.srcNode = srcNode;
        this.tgtNode = tgtNode;
        this.canvas = document.getElementById('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.acceleration = document.getElementById('range');
        this.pathProgress = 0.0;
        this.stepTime = Date.now();
    }
    draw() {
        this.ctx.beginPath();
        this.ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2, false);
        this.ctx.fillStyle = this.color;
        this.ctx.fill();
    }
    update() {
        const STEPSPERSECOND = 10;
        this.nextStepTime = Date.now();
        this.pathProgress += pause * (this.nextStepTime - this.stepTime) * Number(this.acceleration.value) / 100 / 1000 * STEPSPERSECOND / 5;
        this.x = this.srcNode.x + this.pathProgress * (this.tgtNode.x - this.srcNode.x);
        this.y = this.srcNode.y + this.pathProgress * (this.tgtNode.y - this.srcNode.y);
        this.stepTime = this.nextStepTime;
    }
} /* public nodesOA = [];
 public lines = [];
 constructor(public Nodes, ylevels, xlevels) {
   const canvas = document.querySelector('canvas');
   canvas.width = innerWidth;
   canvas.height = innerHeight;
   const ctx = canvas.getContext('2d');
   const lvlHgt = (canvas.height - 200) / ylevels;
   const lvlWdt = (canvas.width - 100) / xlevels;
   const winY = canvas.height >> 1;
   const winX = canvas.width >> 1;

   /*
   ↓ Třída pro zařízení ↓
   */


/***/ }),

/***/ "YnIV":
/*!***********************************!*\
  !*** ./src/app/levels.service.ts ***!
  \***********************************/
/*! exports provided: LevelNodes, getMaxYLevel, getMaxXlevel, GetCyclesByDFS */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "LevelNodes", function() { return LevelNodes; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "getMaxYLevel", function() { return getMaxYLevel; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "getMaxXlevel", function() { return getMaxXlevel; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "GetCyclesByDFS", function() { return GetCyclesByDFS; });
// tslint:disable no-bitwise
function LevelNodes(Nodes) {
    Nodes.sort((a, b) => {
        const ret = (a.ID < b.ID) ? -1 : 1;
        return ret;
    });
    Nodes[0].Ylevel = 1;
    Nodes[0].Xlevel = 0;
    Nodes.forEach(node => {
        let lvl = 0;
        node.connections.forEach(connection => {
            const i = Nodes.findIndex(cNode => cNode.ID === connection);
            node.CardinalityFwd += (Nodes[i].Ylevel === 0) ? 1 : 0;
            Nodes[i].Ylevel = (Nodes[i].Ylevel === 0) ? node.Ylevel + 1 : Nodes[i].Ylevel;
            // ↓ Sudý xlevel předchozího nodu  je záporný xlvl u nového ↓ // tslint:disable no-bitwise
            Nodes[i].Xlevel = lvl++;
        });
    });
    return Nodes;
}
function getMaxYLevel(Nodes) {
    let mlvl = 0;
    Nodes.forEach(node => {
        mlvl = (node.Ylevel > mlvl) ? node.Ylevel : mlvl;
    });
    return mlvl;
}
function getMaxXlevel(Nodes) {
    let mlvl = 0;
    Nodes.forEach(node => {
        mlvl = (node.Xlevel > mlvl) ? node.Xlevel : mlvl;
    });
    return mlvl;
}
function GetCyclesByDFS(Nodes) {
}


/***/ }),

/***/ "ZAI4":
/*!*******************************!*\
  !*** ./src/app/app.module.ts ***!
  \*******************************/
/*! exports provided: AppModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AppModule", function() { return AppModule; });
/* harmony import */ var _angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/platform-browser */ "jhN1");
/* harmony import */ var _angular_common_http__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/common/http */ "tk/3");
/* harmony import */ var _app_component__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./app.component */ "Sy1n");
/* harmony import */ var _network_network_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./network/network.component */ "EilE");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/core */ "fXoL");





class AppModule {
}
AppModule.ɵmod = _angular_core__WEBPACK_IMPORTED_MODULE_4__["ɵɵdefineNgModule"]({ type: AppModule, bootstrap: [_app_component__WEBPACK_IMPORTED_MODULE_2__["AppComponent"]] });
AppModule.ɵinj = _angular_core__WEBPACK_IMPORTED_MODULE_4__["ɵɵdefineInjector"]({ factory: function AppModule_Factory(t) { return new (t || AppModule)(); }, providers: [], imports: [[
            _angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__["BrowserModule"],
            _angular_common_http__WEBPACK_IMPORTED_MODULE_1__["HttpClientModule"]
        ]] });
(function () { (typeof ngJitMode === "undefined" || ngJitMode) && _angular_core__WEBPACK_IMPORTED_MODULE_4__["ɵɵsetNgModuleScope"](AppModule, { declarations: [_app_component__WEBPACK_IMPORTED_MODULE_2__["AppComponent"],
        _network_network_component__WEBPACK_IMPORTED_MODULE_3__["NetworkComponent"]], imports: [_angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__["BrowserModule"],
        _angular_common_http__WEBPACK_IMPORTED_MODULE_1__["HttpClientModule"]] }); })();


/***/ }),

/***/ "tjmI":
/*!*********************************!*\
  !*** ./src/assets/Network.json ***!
  \*********************************/
/*! exports provided: network, default */
/***/ (function(module) {

module.exports = JSON.parse("{\"network\":[{\"id\":\"ids\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"ncia_ids\",\"owner\":\"ncia\"}]},{\"id\":\"defender\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"ncia_defender\",\"owner\":\"ncia\"}]},{\"id\":\"honeypot\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"ncia_honeypot\",\"owner\":\"ncia\"}]},{\"id\":\"pc2\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"rdp\",\"owner\":\"Administrator\"}]},{\"id\":\"pc1\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"rdp\",\"owner\":\"Administrator\"}]},{\"id\":\"server1\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"openssh\",\"owner\":\"bash\"},{\"name\":\"lighttpd\",\"owner\":\"lighttpd\"}]},{\"id\":\"attacker\",\"Type\":\"end-device-fraud\",\"connections\":[],\"services\":[{\"name\":\"attacker_omniscient\",\"owner\":\"attacker\"}]},{\"id\":\"server2\",\"Type\":\"end-device-clear\",\"connections\":[],\"services\":[{\"name\":\"postgresql\",\"owner\":\"postgres\"}]},{\"id\":\"router\",\"Type\":\"router-firewall-clear\",\"connections\":[],\"services\":[]}]}");

/***/ }),

/***/ "zUnb":
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/
/*! no exports provided */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @angular/platform-browser */ "jhN1");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "fXoL");
/* harmony import */ var _app_app_module__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./app/app.module */ "ZAI4");
/* harmony import */ var _environments_environment__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./environments/environment */ "AytR");




if (_environments_environment__WEBPACK_IMPORTED_MODULE_3__["environment"].production) {
    Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["enableProdMode"])();
}
_angular_platform_browser__WEBPACK_IMPORTED_MODULE_0__["platformBrowser"]().bootstrapModule(_app_app_module__WEBPACK_IMPORTED_MODULE_2__["AppModule"])
    .catch(err => console.error(err));


/***/ }),

/***/ "zn8P":
/*!******************************************************!*\
  !*** ./$$_lazy_route_resource lazy namespace object ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

function webpackEmptyAsyncContext(req) {
	// Here Promise.resolve().then() is used instead of new Promise() to prevent
	// uncaught exception popping up in devtools
	return Promise.resolve().then(function() {
		var e = new Error("Cannot find module '" + req + "'");
		e.code = 'MODULE_NOT_FOUND';
		throw e;
	});
}
webpackEmptyAsyncContext.keys = function() { return []; };
webpackEmptyAsyncContext.resolve = webpackEmptyAsyncContext;
module.exports = webpackEmptyAsyncContext;
webpackEmptyAsyncContext.id = "zn8P";

/***/ })

},[[0,"runtime","vendor"]]]);
//# sourceMappingURL=main.js.map