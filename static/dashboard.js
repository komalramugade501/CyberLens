const search = document.getElementById("filter");
if (search) {
  search.addEventListener("input", () => {
    const q = search.value.toLowerCase();
    document.querySelectorAll("#activity tbody tr").forEach(row => {
      row.style.display = row.innerText.toLowerCase().includes(q) ? "" : "none";
    });
  });
}
