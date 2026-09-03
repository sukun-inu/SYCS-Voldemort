import{el,clear}from"./dom.js";function orphanOption(value){return el("option",{value:String(value),text:`${value}（一覧にありません）`});}
export function fillSelect(select,options,{placeholder,value}={}){clear(select);if(placeholder!==undefined){select.append(el("option",{value:"",text:placeholder}));}
select.append(...options.map((o)=>el("option",{value:o.value,text:o.label})));if(value!==undefined)selectValue(select,value);return select;}
export function selectValue(select,value){const wanted=value===null||value===undefined?"":String(value);if(!wanted){select.value="";return false;}
const known=Array.from(select.options).some((o)=>o.value===wanted);if(!known)select.append(orphanOption(wanted));select.value=wanted;return!known;}