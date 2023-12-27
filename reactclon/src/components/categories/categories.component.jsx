import { useState, useEffect } from "react";
import categoryDatas from "api/categories.json";
import Category from "components/category/category.component";
import { ContainerFluidEl, CategoriesContainerEl } from "./categories.styles";
import { ContainerEl, TitleEl } from "common-styles";

const Categories = () => {
  const [categories, setCategories] = useState([]);

  useEffect(() => {
    setCategories(categoryDatas);
  }, []);

  return (
    <ContainerFluidEl>
      <ContainerEl>
        <TitleEl>Kategoriler</TitleEl>
        <CategoriesContainerEl>
          {categories &&
            categories.map((category) => <Category category={category} key={category.id} />)}
        </CategoriesContainerEl>
      </ContainerEl>
    </ContainerFluidEl>
  );
};

export default Categories;
