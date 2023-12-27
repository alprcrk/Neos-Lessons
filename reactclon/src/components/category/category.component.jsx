import { ButtonEl, CategoryContainerEl, ImgEl, TitleEl } from "./category.styles";

const Category = ({ category }) => {
  const { id, title, image } = category;

  return (
    <CategoryContainerEl>
      <ButtonEl>
        <ImgEl src={image} alt={title} />
        <TitleEl>{title}</TitleEl>
      </ButtonEl>
    </CategoryContainerEl>
  );
};

export default Category;
