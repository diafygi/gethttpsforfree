
// hide/show the help content
function howtoContent(e){
    e.preventDefault();
    console.log(e.target.id + "_content");
    var help = document.getElementById(e.target.id + "_content");
    help.style.display = help.style.display === "none" ? "" : "none";
}
function bindHelps(elems){
    for(var i = 0; i < elems.length; i++){
        elems[i].addEventListener("click", howtoContent);
    }
}
bindHelps(document.querySelectorAll(".help"));
