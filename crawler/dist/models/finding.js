"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.emit = emit;
exports.status = status;
exports.error = error;
exports.done = done;
function emit(f) {
    process.stdout.write(JSON.stringify(f) + "\n");
}
function status(message) {
    emit({ type: "status", message });
}
function error(message) {
    emit({ type: "error", message });
}
function done() {
    emit({ type: "done" });
}
