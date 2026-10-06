import React from "react";
const el: JSX.Element = <div className="x" />;
export const run = () => {
    // a comment mentioning eval() must not fire
    return eval("1 + 1");
};
