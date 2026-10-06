// eval("bad") inside a comment is not a sink
const s: string = "eval('1')";
const el: JSX.Element = <div title={"eval(x)"} />;
export const f = () => s;
