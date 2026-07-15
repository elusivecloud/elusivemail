(function() {
  var grid = document.getElementById("provenanceGrid");
  if (!grid) return;

  var commitEl = document.getElementById("provCommit");
  var commitNoteEl = document.getElementById("provCommitNote");
  var digestEl = document.getElementById("provDigest");
  var verifyEl = document.getElementById("provVerify");
  var copyBtn = document.getElementById("provCopy");

  fetch("/.well-known/build-info").then(function(r) {
    return r.ok ? r.json() : null;
  }).then(function(d) {
    if (!d || !d.commit) {
      grid.hidden = true;
      verifyEl.hidden = true;
      return;
    }
    var short = d.commit.slice(0, 7);
    commitEl.innerHTML = "";
    var a = document.createElement("a");
    a.href = d.commitUrl || "#";
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = short;
    commitEl.appendChild(a);
    commitNoteEl.textContent = "The exact revision in " + (d.repo || "the public repo") + ".";

    digestEl.textContent = d.imageDigest ? d.imageDigest.split("@")[1] || d.imageDigest : "not signed (dev build)";

    if (d.verify) {
      verifyEl.textContent = d.verify;
      copyBtn.hidden = false;
      copyBtn.addEventListener("click", function() {
        navigator.clipboard.writeText(d.verify).then(function() {
          var was = copyBtn.textContent;
          copyBtn.textContent = "Copied";
          setTimeout(function() { copyBtn.textContent = was; }, 1500);
        });
      });
    } else {
      verifyEl.textContent = "No signed image for this build. Production reports a real verify command here.";
    }
  }).catch(function() {
    grid.hidden = true;
    verifyEl.hidden = true;
  });
})();
